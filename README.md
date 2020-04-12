# MHA Assessment
All codes are written in Python 3 </br>
**Win32_Industroyer.pdf for part A and http.log for part C are not uploaded. Please add them in your directory if you want to run the scripts.**
## A. Automation Scripting
Scripts are located in folder [A-AutomationScripting](./A-AutomationScripting).
### Part 1
####  To run the script
```
python .\script-1.py -i .\Win32_Industroyer.pdf -o out1     
```
*Note: Output file is automatically saved as txt*

The output from this script has been saved as [out1.txt](./A-AutomationScripting/out1.txt)

### Part 2
#### To run the script
```
python .\script-2.py -i .\Win32_Industroyer.pdf -o out2
```
*Note: Output file is automatically saved as csv*

The output from this script has been saved as [out2.csv](./A-AutomationScripting/out2.csv)

## B. Cyber Threat Analysis
Write up, [B.docx](./B-CyberThreatAnalysis/B.docx), is located in folder [B-CyberThreatAnalysis](./B-CyberThreatAnalysis).

## C. Analytics Development
Script and write up, [C.docx](./C-AnalyticsDevelopment/C.docx), are located in folder [C-AnalyticsDevelopment](./C-AnalyticsDevelopment).
####  To run the script
```
 python .\script-3.py -i .\http.log -o out3
```
There are 2 parameters the users can change.
1. errorT2: Error threshold for percentage of non 200s in status code. The default is 0.5.
+ Example: errorT2 is set as 0.3. If percentage of 200 status code falls below 0.3, the IP will be shortlisted.

2. errorTB: Error threshold for percentage of unknown status in status code. The default is 0.5.
+ Example: errorTB is set as 0.3. If percentage of unknown status code exceeds 0.3, the IP will be shortlisted.

*Note: Output file is automatically saved as txt*

The output from this script has been saved as [out3.txt](./C-AnalyticsDevelopment/out3.txt)
