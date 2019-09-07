## CVE-2019-0708 aka _Bluekeep_

### Scanner

A simple scanner to determine system vulnerability to CVE-2019-0708.

This is a Python port of the original metasploit module scanner by JaGoTu and zerosum0x0, available on Github [here](https://github.com/zerosum0x0/CVE-2019-0708).

### Proof of Concept

Proof of concept RCE via exploitation of the Bluekeep vulnerability.

### Resources

- [Analysis of CVE-2019-0708](https://www.malwaretech.com/2019/05/analysis-of-cve-2019-0708-bluekeep.html) from MalwareTechBlog. Goes through the initial reverse-engineering of the MS patch to the point of discovering DoS via manual binding of channel MS_T120.
- [BlueKeep: A Journey from DoS to RCE](https://www.malwaretech.com/2019/09/bluekeep-a-journey-from-dos-to-rce-cve-2019-0708.html) from MalwareTechBlog. Exactly as advertised.
- [CVE-2019-0708](https://www.zerodayinitiative.com/blog/2019/5/27/cve-2019-0708-a-comprehensive-analysis-of-a-remote-desktop-services-vulnerability) from Zero Day Initiative. An in-depth look at the Bluekeep use-after-free condition. Useful supplement to the other resources.
- [Slides](./resources/Slides.pdf). The first "RCE guide" released to the public. 
