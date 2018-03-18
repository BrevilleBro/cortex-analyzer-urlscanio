# cortex-analyzer-urlscanio

The files should be placed inside a folder "UrlscanIO". 

## Example config within 'application.conf':

key - the API key for UrlScan.IO

public - "on" (share publicly) or "off" (private scan)

```
  UrlScan {
     key="xxxxxxxxxxxxxx"
     public = "off"
   }

```

## Beginners Guide
Installation Steps:

1. Change directories to your cortex analyzers directory and run the following command  
sudo git clone [place url for repo here]

1. Rename the file with the following command  
sudo mv cortex-analyzer-urlscanio/ UrlscanIO/

1. Set the permissions on the UrlscanIO/urlscan.py file  
sudo chmod 755 urlscan.py

If you receive the following error, this is by design to prevent you from leaking sensitive data to public sites.
"errorMessage": "TLP is higher than allowed."

Thanks to @vi-or-die
