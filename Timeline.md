# Timeline 
---
## TL;DR: Contains the timeline and flow of my preparation, not in detail with payload and methods
Every Payload and Methods will be updated When I pass my `EXAM` 
---
## Day 1:
---
Got the access on November 4th,2021 => Download all files => Start reading from start.

Looking at Topics, I could feel the major upgrade from OSCP to OSEP. I was impressed with the course content.
Decided to study PDF first => videos => lab.
spent the day by glancing at the topics and trying to rate my knowledge in the topic.
Decided to spend two days, one each for the PDF and videos

---

## Day 2 to Day 4:
---
Theory of Client Side Code Execution with Office.
I was familiar with using VBA, but the course did have some very in depth content which I found really interesting. Understood key point is to keep it in memory and preferred to use staged payload, as the dropper size can be reduced and detection rate is low. Some of the topic was mainly about code execution post dropper mode, but it did not deal with AV/Defender bypass as yet. Simple Topic shouldn't take much time if you know about macros already.

---

## Day 5 to Day 7
---
### Theory of Client Side Code Execution With Windows Script Host
The flow was similar to that of the macros,
Dropper => Staged Payload => In Memory execution using powershell, c# payload.
Introduction to DotNetToJscript and SharpShooter, although most AV detect the payload now, u can still play around it.
.js file is by default executed by windows, so we don't have to worry about explicitly calling it through an app.
![](/images/Default.png?raw=true)

---

## Day 8 to Day 9
---
### Process Injection and Migration.
Been used to meterpreter doing the steps that we take it for granted.
I really enjoyed reading this part as there was step by step description in theory and video, and I appreciate OFFSEC for explaining the basic steps so neatly.
Worth the time spent here. Has C# and Powershell payloads described in here, 

---

## Day 10 to Day 14
---
### AV evasion
As the Topic says, AV evasion.
This topic is where you have to focus a lot, as the labs have defender and AV over it. Specially AMSI bypass as your gonna need it almost every time you try to get a code exec. Couple of straight methods described in PDF, Your free to use yours (I recommend to keep backup scripts). Since the course has been out, Students have been successful in submitting samples to the AV vendors, which leads to detection of our payload, To not worry/panic during lab/exam please prepare your own script, even a slight modification in Dropper code is sometimes enough to bypass some AV, so obfuscation is really important. It shows the payload generation for Macros, C#, and Powershell. So this is one of the important topic.

On  Day 11, I start my Lab 1: Took a couple of days to actually understand, as I was stuck on it with the OSCP mindset to get a foothold => user shell => priv shell. But that is not the aim in here. Our target is DC,  so focus more on pivot and AD. To try and test your code, you are provided with a test Win 10 VM, but i would recommend having your own VM for testing. **NOTE**
`Please Disable Windows Defender and any other AV if you have installed in your Host while testing . If your using a shared directory on you host windows, Please make sure you add the shared directory on whitelist or ignore list and disable sample submission in your Defender. I would recommend disable NAT/Bridged mode network to test VM, preventing it from accessing the internet.`
I had to refer to Application Whitelisting as we are gonna use AMSI bypass together with CLM bypass, so get a good payload ready for your exam.

---
## Day 15 and Day 16
---
Still stuck on lab 1. Trying to understand pivot paths, Basic Active Directory introduction in here. There will be occasional jumps between topics like AV bypass, AD, Process injection, etc. So it was good run between multiple topics. The focus in here is about trying to reach DC as soon as possible. Check if you can priv esc quickly, else find path, creds or any info from AD enum to pivot into next IP. 
**Focus on Movement**
PowerView, BloodHound and Metasploit are your best friends in the lab. Get a hang of them.
Lab 2 was a breeze, PDF is more than enough for you guys, couple of hours your done.
Lab 3 was interesting. its like, every lab covers a part of PDF, so not trying the individual modules in practice will definitely consume more time while solving the labs, but you are free to experiment yourself.

---
### NEED A BREAK FOR COUPLE OF DAYS, TOO HECTIC SCHEDULE FROM THE START OF LABS
I am a University student, Juggling between classes and OSEP and other stuff

---
Day 19
---
I shift my focus onto labs only for now, Will refer the PDF and notes when required.
Lab 4 sets the path towards the exam. 3 days to get all flags, now I realize my AD needs some serious work.


---
## Day 23
Lab 5 was weird w.r.t starting the lab, I had to revert the labs thrice to get the machine to spawn. i'm on day 26 just a couple more box left. This was some real pivoting and AD, and i guess i have the expectation of what LAB 6 beholds, which OFFSEC says is as close as it gets to the exam. I would like to solve it without any nudges.

---

## Day 26
---
Done with lab 5, Kind of tricky, but AD is really important.

---

## Day 27
---
Starting Lab 6 , took a week to understand lot of stuff, some things were new, some assumptions, some classic misconfig.
As much as I wanted to solve without hints, I had to rely on some pointers to figure it out. Kinda sad, but worth it as I learned some new tricks and accessed some good repos which were really useful w.r.t exam.

---

## Day 34
---
All labs done, Took quite a long break for 10 days.

---

## Day 45
---
Refreshing through all labs, rechecking all payloads and stuff.
Found some really nice code for dropper, and finally managed 0 detections in static analysis
I feel confident enough to schedule exam on Jan 2nd.

---

## Day 53 to Exam Day
---
What happens when you are way too optimistc. End up with Covid right after boxing day.
A sane person would have rescheduled his exam, but not me, was way too optimistic and eager to finish the exam, and dint reschedule.
Biggest mistake, 
```
Never take any exam/task right after recovery or you feel recovered after illness. The Medications make you drowsy and hampers your thinking ability
```

---

# Exam Day
---
Nothing works according to plan.
- Payload fails. 
- Initial Enum is $#!&.
- Medicines making drowsy.
- My brain is not working.

24 hours in and only one flag, made me question my skills. A simple priv esc dint work and the panic steps in. 

Mistakes:
- No breaks.
- Dint Focus on  having my food at right time.
- Panicked.
- Lack of sleep.

Decided to take a long break. Slept and started again.
Got 4 more flags pretty quickly. High on confidence now until I hit a roadblock and lost my mind again. Finally with some sense in my head decided to quit the exam and focus on my mental health and physical health. 
A good Decision as I needed couple more days to recover completely.

---
```
I failed the exam, Not at all happy, and a poor start to the year, very depressed.
```

Positives From the Experience:
- I can work under stress, not the optimal result but I can withstand pressure and perform tasks.
- Understood importance of good health and breaks (Should have known about breaks from OSCP exam; -_- ).
- Can think and analyze out of box and restart the task from basics to succeed.

---



