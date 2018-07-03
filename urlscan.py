#!/usr/bin/env python
# encoding: utf-8


from cortexutils.analyzer import Analyzer
import requests
import time
from io import BytesIO
from base64 import b64encode

class UrlscanAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.getParam(
            'config.service', None, 'Service parameter is missing')
        self.api_key = self.getParam('config.key', None, 'Missing UrlScan.io API key')
        self.public = self.getParam('config.public', "off")


    def summary(self, raw):
        taxonomies = []

        if int(raw['UrlScan']['urlscan_response']['malicious']) > 0:
            predicate = "Malicious"
            level = "malicious"
            value = "True"
        else:
            predicate = "Requests"
            level = "info"
            value = len(raw['UrlScan']['urlscan_response']['request_response_chain'])


        taxonomies.append(self.build_taxonomy(level, "UrlScan.IO", predicate, value))

        result = {"taxonomies":taxonomies}
        return result

    def scan_url(self, url):
        headers = {
            'Content-Type': 'application/json',
            'API-Key': self.api_key,
        }

        data = '{"url": "%s"}' % url
        response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, data=data)
        #r = response.content.decode("utf-8")

        if response.status_code == 200:
            uuid = response.json()["uuid"]
            self.grab_report(uuid)
        elif response.status_code == 429:
            time.sleep(2)
            self.scan_url(url)
        else:
            self.error("An error occurred submitting the URL/Domain to UrlScan.io. \n Header: {0} \n Message: {1} ".format(
                response.status_code,
                response.content))

    def grab_report(self, uuid):
        response = requests.get("https://urlscan.io/api/v1/result/%s" % uuid)

        if response.status_code == 404:
            time.sleep(20)
            self.grab_report(uuid)
        elif response.status_code == 200:
            screenshot = BytesIO(requests.get("https://urlscan.io/screenshots/%s.png" % uuid).content)
            img_base64 = (b64encode(screenshot.getvalue())).decode("utf-8")

            dom = requests.get("https://urlscan.io/dom/%s/" % uuid).content.decode("utf-8")

            request_response_chain = {}

            request_index = 0
            for request in response.json()['data']['requests']:
                request_response_chain[request_index] = {}
                if 'request' in request['request']:
                    request_response_chain[request_index]["mime_type"] = request['request']['type'] if 'type' in request['request'] else ''
                    request_response_chain[request_index]["method"] = request['request']['request']['method'] if 'method' in request['request']['request'] else ''
                    request_response_chain[request_index]["request_url"] = request['request']['request']['url'] if 'url' in request['request']['request'] is not '' else ''
                else:
                    request_response_chain[request_index]["mime_type"] = ''
                    request_response_chain[request_index]["method"] = ''
                    request_response_chain[request_index]["request_url"] = ''


                if 'response' in request:
                    if 'response' in request['response']:
                        request_response_chain[request_index]["response_status"] = request['response']['response']['status'] if 'status' in  request['response']['response'] else ''
                        request_response_chain[request_index]["response_IP_PORT"] = "{0}:{1}".format(request['response']['response']['remoteIPAddress'], request['response']['response']['remotePort']) if 'remoteIPAddress' in request['response']['response'] is not '' else ''
                        request_response_chain[request_index]["ip_whois_name"] = request['response']['asn']['name'] if 'asn' in request['response'] else ''
                else:
                    request_response_chain[request_index]["response_status"] = ''
                    request_response_chain[request_index]["response_IP_PORT"] = ''
                    request_response_chain[request_index]["ip_whois_name"] = ''

                if 'requests' in request:
                    redirects = []
                    for inner_request in request['requests']:
                        redirects.extend([inner_request['request']['url']])
                    request_response_chain[request_index]["redirects"] = redirects
                else:
                    if 'redirectResponse' in request['request']:
                        redirects = []
                        redirects.insert(0, request['request']['redirectResponse']['url'])
                        redirects.insert(1, request['request']['request']['url'])
                        request_response_chain[request_index]["redirects"] = redirects


                request_index += 1

            if 'redirects' in request_response_chain[0]:
                effective_url = request_response_chain[0]['redirects'][-1]
            else:
                effective_url = ''

            formatted_response = {
                "ips" : response.json()['lists']['ips'],
                "countries" : response.json()['lists']['countries'],
                "domains" : response.json()['lists']['domains'],
                "urls" : response.json()['lists']['urls'],
                "linkDomains" : response.json()['lists']['linkDomains'],
                "certificates" : response.json()['lists']['certificates'],
                "asns": response.json()['lists']['asns'],
                "page" : response.json()['page'],
                "task" : response.json()['task'],
                "malicious" : response.json()['stats']['malicious'],
                "adBlocked" : response.json()['stats']['adBlocked'],
                "effective_url" : effective_url,
                "request_response_chain" : request_response_chain
            }


            build_report = {"urlscan_response": formatted_response,
                            "urlscan_screenshot": img_base64,
                            "urlscan_dom" : dom
                            }

            self.report({"UrlScan":build_report})
        else:
            self.error("An error occurred retrieving the report for the URL/Domain to UrlScan.io. \n Header: {0} \n Message: {1} ".format(
                response.status_code,
                response.content))


    def run(self):
        if self.service == 'scan':
            if self.data_type == 'url' or self.data_type == "domain":
                data = self.getParam('data', None, 'Data is missing')
                r = self.scan_url(data)
            else:
                self.error('Invalid data type')
        else:
            self.error('Invalid service')


if __name__ == '__main__':
    UrlscanAnalyzer().run()
