---
title: "CYBERGAME-2025 {PROCESS AND GOVERNANCE}"
subtitle: "⚡ felt like GRC,but cool⚡"
summary: "* Kenyan version organized by: Ministry of Information,Communications and the Digital Economy*"
date: 2025-06-11
cardimage: cybergame.png
featureimage: cybergame.png
caption: cybergame
authors:
  - Havoc: logo.png
---


# [★☆☆] Reading the dusty books

## Handling

**Description**

1. There was a large incident in a water treatment facility. It required response from various CSIRT teams, providing live system analysis, forensics, malware analysis, ICS expertise and other roles. You overheard a guy from team A talking about choosing a containment strategy. A guy from team B talking about containment and eradication stage. A guy from team C talking about evidence gathering and handling. Identify which two teams are likely using the same incident handling methodology.
    
2. In one of the two leading standards on cybersecurity incident handling, there is a chapter Access Control under Type of incidents. Looking at the second word of the text from that chapter, how many letters are there?
    
3. In ENISA incident guide table of contents, which chapter has the same colour as the iconic object on the picture on the same page? Answer in uppercase, no spaces.
    
4. In the same document, there is a diagram which looks like a downward pointing arrow. What is the stage on the tip of the arrow? Answer in uppercase, no spaces.
    
5. SANS methodology for incident handling specifically mentions some operating systems. Out of those, which is the least frequently mentioned one? Answer in uppercase, no spaces.
    

Flag format: answers, separated by dash:

- two letters from the first question, i.e. one of AA, AB, AC, BC (two letters, uppercase, nothing else)
- number answering the second question
- name of the chapter, all letters uppercase, no spaces (if any).
- stage, all letters uppercase, no spaces (if any)
- name of the operating system

For example, if your answers were

1. CD (of course there is no letter D, are we clear?)
2. 9
3. NAMEOFTHECHAPTER
4. SOMESTAGE
5. BEOS

Then the flag will be

CD-9-NAMEOFTHECHAPTER-SOMESTAGE-BEOS

Submission limit is 20

Solution

1. [NIST SP 800-61r2](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-61r2.pdf); 3.3.1 Choosing a Containment Strategy and 3.3.2 Evidence Gathering and Handling thats **AC**
2. ISO/IEC 27035-1:2023, Annex B, B.1 Type of incidents, B.1.5 Access control; Second word is `access`
3. [ENISA - Good Practice Guide for Incident Management](https://www.enisa.europa.eu/sites/default/files/publications/Incident_Management_guide.pdf), iconic object
![truck](https://github.com/Daniel-wambua/blogz/blob/main/content/CTF/writeup7/images/truck.png?raw=true) being a red fire truck, the chapter that is red in ToC is `Workflows`.
![truck](https://github.com/Daniel-wambua/blogz/blob/main/content/CTF/writeup7/images/2025-06-11_14-16.png?raw=true)
4. Same document,
   ![doc](https://github.com/Daniel-wambua/blogz/blob/main/content/CTF/writeup7/images/arrow%20down.png?raw=true)     Figure 6 - Incident handling workflow, tip of the arrow is `IMPROVEMENT PROPOSALS`.
5. Here I was not exactly sure which document it should be, I went based on [Incident Handler's Handbook](https://dl.icdst.org/pdfs/files3/d60a0c473353813ed1f32c4faefedbd6.pdf), looking for operating systems `Linux` appeared to be mentioned but very few times.

```
AC-6-WORKFLOWS-IMPROVEMENTPROPOSALS-LINUX
```

## Colors of the rainbow

[](https://github.com/lukaskuzmiak/cybergame.sk-2025-writeups/tree/main/Reading%20the%20dusty%20books#colors-of-the-rainbow)

Description

1. Which two of these colors are most related to common criteria? (uppercase, comma separated) RED / ORANGE / YELLOW / GREEN / BLUE / INDIGO / VIOLET
    
2. The ENISA incident handling book, which we already mentioned, has this nice truck. What is the color of the longest part of the truck? BLUE / RED / GRAY / BLACK / WHITE
    
3. The NIST standard has a different first responder's truck on some diagram. Which is true: 1 it is a police van 2 the driver of the truck is a bald male 3 the driver of the truck is a young female 4 the truck is a 6-wheeler 5 the truck looks at the shield and a sword 6 the truck travels towards the tree
    

Flag format: answers, separated by dash:

- colors from the list, uppercase, comma separated, in the order from the list.
- color from the list, uppercase
- the number of the correct statement

For example, if your answers were

- RED,CYAN
- GREEN
- 9

Then the flag will be RED,CYAN-GREEN-9

Submission limit is 20 flags

Solution

1. One color I was able to identify as related to Common Criteria was RED. I am not sure where the ORANGE was supposed to be found  but guess work helped here.inshallah!
2. [ENISA - Good Practice Guide for Incident Management](https://www.enisa.europa.eu/sites/default/files/publications/Incident_Management_guide.pdf), the longest part being the ladder which is white.
3. [NIST SP 800-61r3](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-61r3.pdf); 2.1. Incident Response Life Cycle Model; "5 the truck looks at the shield and a sword"

![rainbow](https://github.com/Daniel-wambua/blogz/blob/main/content/CTF/writeup7/images/colors_of_the_rainbow_3.jpg?raw=true)

```
RED,ORANGE-WHITE-5
```
