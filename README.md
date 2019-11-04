## CVE-2019-0708 aka _Bluekeep_

### Scanner

A simple scanner to determine system vulnerability to CVE-2019-0708.

This is a Python port of the original metasploit module scanner by JaGoTu and zerosum0x0, available on Github [here](https://github.com/zerosum0x0/CVE-2019-0708).

### Proof of Concept

Proof of concept RCE via exploitation of the Bluekeep vulnerability.

### Related

- [0xeb-bp Github: bluekeep](https://github.com/0xeb-bp/bluekeep). Pointed out by zerosum0x0, has code for grooming MS_T120 on XP.

### Resources

**Popular Press Coverage**

- [The First Bluekeep Mass Hacking is Here - But Don't Panic](https://www.wired.com/story/bluekeep-hacking-cryptocurrency-mining/)

**Research**

- [Slides](./resources/Slides.pdf). The first "RCE guide" released to the public. 
- [Three Ways to Write Data into the Kernel with RDP PDU](https://unit42.paloaltonetworks.com/exploitation-of-windows-cve-2019-0708-bluekeep-three-ways-to-write-data-into-the-kernel-with-rdp-pdu/). Potential kernel pool grooming methods.
- [Analysis of CVE-2019-0708](https://www.malwaretech.com/2019/05/analysis-of-cve-2019-0708-bluekeep.html) from MalwareTechBlog. Goes through the initial reverse-engineering of the MS patch to the point of discovering DoS via manual binding of channel MS_T120.
- [BlueKeep: A Journey from DoS to RCE](https://www.malwaretech.com/2019/09/bluekeep-a-journey-from-dos-to-rce-cve-2019-0708.html) from MalwareTechBlog. Exactly as advertised.
- [CVE-2019-0708](https://www.zerodayinitiative.com/blog/2019/5/27/cve-2019-0708-a-comprehensive-analysis-of-a-remote-desktop-services-vulnerability) from Zero Day Initiative. An in-depth look at the Bluekeep use-after-free condition. Useful supplement to the other resources.
- [Bluekeep Exploitation Spotted in the Wild](https://www.wired.com/story/bluekeep-hacking-cryptocurrency-mining/)

**Writeups**

- [How to Exploit Bluekeep Vulnerability with Metasploit](https://pentest-tools.com/blog/bluekeep-exploit-metasploit/). Another early post demonstrating the platform-dependent tweaks needed for successful exploitation.
- [A Debugging Primer with CVE-2019-0708](https://medium.com/@straightblast426/a-debugging-primer-with-cve-2019-0708-ccfa266682f6). A walkthrough of the UAF condition via kernel debugger.
- [Playing with the Bluekeep Metasploit Module](https://klaus.hohenpoelz.de/playing-with-the-bluekeep-metasploit-module.html). An early blog post regarding tweaks needed to get the exploit to work on a particular platform.

**The _RDPSND_ Problem**

- [Registry Keys for Terminal Services](http://etutorials.org/Microsoft+Products/microsoft+windows+server+2003+terminal+services/Chapter+6+Registry/Registry+Keys+for+Terminal+Services/). Relating to the non-default registry key that must be set in order to groom via RDPSND virtual channel as in the open-source exploit.
- [Windows Security Encyclopedia: Allow Audio and Video Playback](https://www.windows-security.org/350b68430b7c7cc38e49ef84ad7b592e/allow-audio-and-video-playback-redirection). A quick rundown relating to how registry controls audio and video redirection, relating to RDPSND virtual channel.
