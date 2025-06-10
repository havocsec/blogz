---
title: "CYBERGAME-2025 {OSINT CHALLENGES}"
subtitle: "⚡ Gonna be a detective,Osint is cool than ever⚡"
summary: "* Kenyan version organized by: Ministry of Information,Communications and the Digital Economy*"
date: 2025-06-10
cardimage: cybergame.png
featureimage: cybergame.png
caption: cybergame
authors:
  - Havoc: logo.png
---

# [★★★] Suspect tracking

## Identification

![osint](https://github.com/Daniel-wambua/blogz/blob/main/content/CTF/writeup4/images/osint2222.png?raw=true)

the image above.

![photo.jpg](https://media.githubusercontent.com/media/lukaskuzmiak/cybergame.sk-2025-writeups/main/Suspect%20tracking/Identification/identification.jpg)

**Solution**

i performed some seaches and It seems the `photo.jpg` is from [Best_Western_Premier_Malta-St_Paul_s_Bay_Island_of_Malta](https://www.tripadvisor.com/Hotel_Review-g608946-d27536201-Reviews-Best_Western_Premier_Malta-St_Paul_s_Bay_Island_of_Malta.html)

Identified the hotel in the image and found it on Google - [Best Western Premium Hotel Malta ](https://www.google.com/travel/search?q=best%20western%20premier%20malta&g2lb=4965990%5B%E2%80%A6%5DCCQklcUD-ue1Ax0IJCSVxQP657UDHSAA&ap=MAC6AQdyZXZpZXdz&ictx=111) One of the reviews on that page ^ was made by a nigga by the alias`cybergameosintplayer` - which is linked from tripadvisor and it  says:

> I recently stayed at this hotel and had a pleasant overall experience. The check-in process was smooth and the staff were friendly and helpful throughout my stay. …

On **TripAdvisor** - you can search in the reviews for the first line. Bringing you this review that seems to match [https://www.tripadvisor.com/ShowUserReviews-g608946-d27536201-r1000507523-Best_Western_Premier_Malta-St_Paul_s_Bay_Island_of_Malta.html](https://www.tripadvisor.com/ShowUserReviews-g608946-d27536201-r1000507523-Best_Western_Premier_Malta-St_Paul_s_Bay_Island_of_Malta.html)

Click on the user Jolaus profile - [https://www.tripadvisor.com/Profile/cybergameosintplayer?fid=cf222a74-0656-4ceb-a826-aea95aa2289d](https://www.tripadvisor.com/Profile/cybergameosintplayer?fid=cf222a74-0656-4ceb-a826-aea95aa2289d) and see in his intro the first flag

`SK-CERT{h0t31_r3vi3w_f14g}`

## Localization

![osint](https://github.com/Daniel-wambua/blogz/blob/main/content/CTF/writeup4/images/localization.png?raw=true)


**Solution**

Identify the image - and the image is as you see ![picture taken](https://dynamic-media-cdn.tripadvisor.com/media/photo-o/2f/7c/29/1e/caption.jpg)
- within 5 digits of latitude/longitude

The Hotel is at "Triq It-Tamar, St. Paul's Bay, Island of Malta SPB 1281 Malta"

It is quickly clear this is "Fungus Rock, Malta" that we are seeing. Problem is finding the exact location with precision of 5 decimal digits of lat/lng.

I spent some time finding all possible images of Fungus rock that had GPS coordinates to them. I created a project in Google Earth and marked them all there with pins. Then comparing all of them (their angle, distance, etc.) to the challenge image, I was able to narrow down an area I believed was where the image was taken.

After a couple of tries , I came up with these coordinates:

```
36.04863,14.19105
```

## Golden hour

![osint](https://github.com/Daniel-wambua/blogz/blob/main/content/CTF/writeup4/images/golden%20hour.png?raw=true)



**Solution**

So, we know the location of the image now, we see how high the sun is above the horizon. I figured the best would be to use one of many libraries that can calculate sunset time and sun azimuth at a specific time.

I used [SunCalc](https://www.suncalc.org/) to determine the approximate azimuth of the sun in the image—just by moving the sun around until the azimuth line roughly matched with the peninsula—compared to the image. By doing that I figured the azimuth of the sun at the time in the image must be around 246° approximately.

Then I wrote [`golden_hour.py` 

```python
from datetime import date, timedelta, time, datetime

import pytz
from astral import LocationInfo
from astral.sun import sun, azimuth as sun_azimuth

loc = LocationInfo(timezone="CET", latitude=36.04865, longitude=14.19105)

print(loc.timezone)

d = date(2025, 1, 1)
while d.year == 2025:
    s = sun(loc.observer, date=d, tzinfo=pytz.timezone(loc.timezone))['sunset']
    # if s.hour == 17 and s.minute == 14:
    #     print(d)
    if s.hour == 17:
        date_time = pytz.timezone(loc.timezone).localize(datetime.combine(d, time(17, 14)))
        azimuth = sun_azimuth(loc.observer, date_time)
        print(f'date {d} - sunset at {s.hour}:{s.minute}, azimuth at 17:14 is {azimuth:.3f}')
    d += timedelta(days=1)
```
to calculate the sunset times + azimuth of the sun at 17:14—the time on the picture. I then split it up by what I thought was close enough to my estimate:

```
there are probably too early, sunset the pic is at least 4-5 minutes away
date 2025-01-17 - sunset at 17:14, azimuth at 17:14 is 244.798
date 2025-01-18 - sunset at 17:15, azimuth at 17:14 is 244.912
date 2025-01-19 - sunset at 17:16, azimuth at 17:14 is 245.032
date 2025-01-20 - sunset at 17:17, azimuth at 17:14 is 245.159

somewhere here?
date 2025-01-21 - sunset at 17:18, azimuth at 17:14 is 245.293
date 2025-01-22 - sunset at 17:19, azimuth at 17:14 is 245.433
date 2025-01-23 - sunset at 17:20, azimuth at 17:14 is 245.580
date 2025-01-24 - sunset at 17:21, azimuth at 17:14 is 245.733
date 2025-01-25 - sunset at 17:22, azimuth at 17:14 is 245.892
date 2025-01-26 - sunset at 17:23, azimuth at 17:14 is 246.058
date 2025-01-27 - sunset at 17:24, azimuth at 17:14 is 246.230
date 2025-01-28 - sunset at 17:25, azimuth at 17:14 is 246.408
date 2025-01-29 - sunset at 17:26, azimuth at 17:14 is 246.592
date 2025-01-30 - sunset at 17:27, azimuth at 17:14 is 246.783
date 2025-01-31 - sunset at 17:28, azimuth at 17:14 is 246.980
date 2025-02-01 - sunset at 17:29, azimuth at 17:14 is 247.182

these are probably too late (past sunset) or azimuth too high
date 2025-02-02 - sunset at 17:31, azimuth at 17:14 is 247.391
date 2025-02-03 - sunset at 17:32, azimuth at 17:14 is 247.605
date 2025-02-04 - sunset at 17:33, azimuth at 17:14 is 247.825
date 2025-02-05 - sunset at 17:34, azimuth at 17:14 is 248.050
date 2025-02-06 - sunset at 17:35, azimuth at 17:14 is 248.282
date 2025-02-07 - sunset at 17:36, azimuth at 17:14 is 248.519
date 2025-02-08 - sunset at 17:37, azimuth at 17:14 is 248.761
date 2025-02-09 - sunset at 17:38, azimuth at 17:14 is 249.008
date 2025-02-10 - sunset at 17:39, azimuth at 17:14 is 249.261
```

also tried the suncalc to compare and it came cool and perfect.
After a few tries I came up with the answer -

`0130`. 

 ## **OSINT CHALLENGE 2**
 
 # [★☆☆] The digital trail
##  The tip

![osint](https://github.com/Daniel-wambua/blogz/blob/main/content/CTF/writeup4/images/the%20digital%20trail%20the%20tip.png?raw=true)


**Solution**
i goggled dorked and found the exact repository  corresponding to the link we were given in the challenge as : [DATASHIELD-WEB](https://github.com/alexmercer-dev/datashield-web/)

At the bottom of the  `README.md` theres this : `U0stQ0VSVHtoMWRkM25fMW5fcGw0MW5fczFnaHR9`

```shell
 echo U0stQ0VSVHtoMWRkM25fMW5fcGw0MW5fczFnaHR9 | base64 -d
SK-CERT{h1dd3n_1n_pl41n_s1ght}
```

## The evidence

![osint](https://github.com/Daniel-wambua/blogz/blob/main/content/CTF/writeup4/images/the%20evidence.png?raw=true)


**Solution**

In the [`commit here`](https://github.com/AlexMercer-dev/datashield-web/pull/6/commits/d76658afa4964698f6ffaebe4968110117c1b5bb#diff-66890216d671b1c02636e231ae893ae7e4833c163ffa1606dc58c85a7250a9e9), on this  file `docs/static/js/analytics-enhanced.js`, on  line 144 we found the flag as a comment.

```
SK-CERT{m4l1c10us_c0mm1t_d3t3ct3d}
```

## The digital footprint

![osint](https://github.com/Daniel-wambua/blogz/blob/main/content/CTF/writeup4/images/the%20digital%20footprint.png?raw=true)


*Solution*

After a cool google dorking i Found posts from `evanmassey1976` on reddit.com, the post with the flag is: [THE POST](https://www.reddit.com/user/evanmassey1976/comments/1kpmiaw/security_practices_that_are_actually_underrated/)

The flag is hidden on the first line of each sentense so Take the first letter of each line then boom the flag.

```
SK-CERT{S0C14L-M3D14-0S1NT-TR41L}
```

## The private channel

![osint](https://github.com/Daniel-wambua/blogz/blob/main/content/CTF/writeup4/images/the%20private%20channel.png?raw=true)


*Solution*

The user `evanmassey1976` on reddit.com included a discord invite, in the #random channel some bots are talking and mention this:

> ***Aleah Franco*** Note to self: Password for Mark's channel is 'ReallySecretNobodyKnowsAboutThisPassword'. Need to keep this safe. SK-CERT{d1sc0rd_b0t_s3cr3ts}

`SK-CERT{d1sc0rd_b0t_s3cr3ts}`

That is the third flag.

## The escape plan

![osint](https://github.com/Daniel-wambua/blogz/blob/main/content/CTF/writeup4/images/the%20escape%20plan.png?raw=true)


*Solution*

- To join the secret channel one has to DM Mark Wesley and send the password as`ReallySecretNobodyKnowsAboutThisPassword`
- You are then added to the #hacking channel. There is an **image**  
  ![osint](https://github.com/Daniel-wambua/blogz/blob/main/content/CTF/writeup4/images/discord%20image.png?raw=true)
- posted of a forum where all the operations are being migrated to.
- In the descriptive text of that image, still in Discord you will find the text `freirehf-fancr.rh`.
- This is ROT13 of the domain `serverus-snape.eu`.

This domain has a TXT record with a weird looking base64:

```shell
host -t ANY serverus-snape.eu
...
serverus-snape.eu descriptive text "U0stQ0VSVHtkbnNfcjNjMHJkXzFuc3AzY3Qwcn0="
...
```

Decoding that leads to the final flag of this challenge:

```shell
echo 'U0stQ0VSVHtkbnNfcjNjMHJkXzFuc3AzY3Qwcn0=' | base 64 -d
SK-CERT{dns_r3c0rd_1nsp3ct0r}
```

---

*Thats it on osint challenges,*

---
