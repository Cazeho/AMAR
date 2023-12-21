# AMAR
Automatic Malware Analysis Report

## GOAL

make an integration of malware static analysis in Cortex XDR as an API with backend Minio storage 

pdf have a part of filling for behavioral analaysis

For malware category and dll add search chatgpt with openai API

dev external analysis with API like VT & Tria.ge sandbox

Terraform deployment (in progress)

## POC

![AMAR drawio](https://github.com/Cazeho/AMAR/assets/58745332/a56b1077-6e03-431c-8a20-3a2b9f6b8374)


## Tools

| File Extension | Tools          |
| -------------- | -------------- |
|    utility            |      capa, floss           |
| generic           | file , strings, grep, sha256sum, md5sum, xxd, stringsifter, binwalk |
| .docx / .xlsx  / .vbs        | oledump, oleid, olevba, oleobj, msodde, oletools        |
|   .zip       | zipdump       |
| .pdf           |  rtfobj,  pdf-parser.py, peepdf, pdfid   |
| .lnk           | lnkparser -j  |
| .exe / .elf           | objdump, pestudio, readelf, capa https://github.com/mandiant/capa  |
| .js           |  |



decoder => https://github.com/DidierStevens/DidierStevensSuite (base64dump)

scan file => pescan, clamscan, https://github.com/decalage2/balbuzard

https://github.com/DidierStevens/DidierStevensSuite/tree/master

https://unit42.paloaltonetworks.com/tools/


## youtube

https://www.youtube.com/@c3rb3ru5d3d53c

https://www.youtube.com/@informationsecurityclubuca8207

https://www.youtube.com/@CryptoWare

https://www.youtube.com/@0xdf

https://www.youtube.com/@huskyhacks

https://www.youtube.com/@BretWitt

https://www.youtube.com/@pcsecuritychannel

## website

https://malapi.io/


