# D Day - 02
---
## Offsec were kind enough to let me retake my exam without cooldown period of 1 month (Will not disclose the reason.) I am thankful to Offsec for letting me retake quickly.

---
## Prep after first fail.
- Only one prep, went through google to learn more about the path I got stuck, got some lead, time to test in exam. It worked.
- Really nothing else, no labs, not extension, no blogs.
---
## The Exam 
- Exam was a breeze, got the minimum required flags well under time, had lots of time to go through various methods and test my hypothesis.
- Did I get secret.txt? 
	- unfortunately Nooooooooo. 
- How close was I ?
	- I guess just one hop away, Not 100% sure as I could see the box.
	- I had more flags than the 10 required.
- Will I give the exam again to get to secret.txt 
	- Yes, Someone pay for my retest XD.
- Was the Exam environment stable?
	- Yes 
	- But, after a reset I don't know why, the initial payload dint work, had to reset to exploit again, works like a charm. This happened only once.
	- Had to trigger the payload multiple times, maybe it is the design.
	- Nothing is broken. Yes nothing is broken, I initially thought the same, but later figured out it was not broken. Like OSCP, You have to tweak your payloads a lil to get execution.
---
Offsec Clearly states in its FAQ:
```
The exam consists of one large network with multiple machines that must be compromised. As the exam network simulates a corporate network, you will have to first obtain a foothold and then perform additional internal attacks. There are multiple attack paths through the network that will result in the same level of compromise.

Some of the machines will require multiple exploitation steps, resulting first in low-level local access, and then in root or administrative privilege escalation. Other machines will be fully exploitable remotely.

While we cover a number of more advanced techniques in this course, foundational attack components are also part of the exam.

Specific instructions for your target network will be located in your Exam Control Panel, which will only become available to you once your exam begins.
```

With the above FAQ's one Shouldn't really struggle with the exam, although I made some silly mistakes (We all do at some stages, nothing to be ashamed off).
- Yes there is more than one way to compromise/ get foothold.
- `While we cover a number of more advanced techniques in this course, foundational attack components are also part of the exam.` 
	- I want to stress on this line more because I saw people complain about certain vectors.
	- Do not forget your fundamentals, you learnt this in OSCP. Use the same tricks.
	- Do not call this as out of syllabus. It is nothing difficult, you would have done the same tricks in OSCP labs and exam. Use the same skillset here.
	- Google whatever you don't understand. I believe you should know how to google lil pieces of information available to you => Follow the path => connect the dots => You have what you need. Go get that shell.
- You don't need to compromise every machine to pass, Just go with the flow of where the exploitation and enumeration leads you.
---
## My review of Exam
- The foothold was similar to lab, nothing new.
- Pivot also similar to labs.
- Does the lab and pdf cover what is required for the exam?
	- Yes and no.
	- No: Like OSCP no exact copy paste of the techniques. I felt the labs could have been a little more complex w.r.t the payloads crafted in the exam. 
	- Don't be discouraged with the above point. You will be able to figure out the solutions when your stuck, just take a break and start from scratch with the details you have.
- Do you need other labs and courses ?
	- No, I had zero experience w.r.t AD and Defender evasion.
	- W.R.T learning, please do refer other resources as some techniques are better explained and simple to use when compared with the PDF and videos.
	- It is an advantage as you will learn new topics and methods which you can implement in the exam.
- Keep backup payloads. I recommend to keep at least one good payload to get a RCE even if you don't get a shell.
- Take breaks, It is doable, Don't lose focus.
---
