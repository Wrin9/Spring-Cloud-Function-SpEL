# Spring-Cloud-Function-SpEL
## Spring-Cloud-Function-SpEL_POC_EXP
### 此代码是利用dnslog回显，确认是否存在漏洞，延时设置5s，可以按照所处环境修改延时时间。
This code uses the dNSlog echo to confirm whether there is a vulnerability. The delay time is set to 5s, and the delay time can be modified according to the environment.
### POC:
pocsuite -r Spring-Cloud-Function-SpEL_POC_EXP.py -u url --verify
![poc](https://user-images.githubusercontent.com/54984589/160617916-6e1a6daa-eade-4579-a2ec-79069d015c55.gif)
### EXP:
pocsuite -r Spring-Cloud-Function-SpEL_POC_EXP.py -u url --attack --command "[command]"
![exp](https://user-images.githubusercontent.com/54984589/160618090-3c9aa365-11b5-49e1-969b-e74463ee2a47.gif)
# 免责声明
## 此工具仅用于学习、研究和自查。不应将其用于非法目的。使用本工具产生的一切风险与我无关！
# Disclaimer
## This tool is for study, research, and self-examination only. It should not be used for illegal purposes. All risks arising from the use of this tool have nothing to do with me!
