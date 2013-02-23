Do you see writing a security tool in windows is hard?

Do you have a great idea but you can’t implement it?

Do you have a good malware analysis tool and you don’t need it to become a plugin in OllyDbg? or IDA Pro?

So, Security Research and Development Framework is for you.

Do you need a free licence for your commercial project? join us

--------------------
Abstract:
--------------------

This is a free open source Development Framework created to support writing security tools and malware analysis tools. And to convert the security researches and ideas from the theoretical approach to the practical implementation.

This development framework created mainly to support the malware field to create malware analysis tools and anti-virus tools easily without reinventing the wheel and inspire the innovative minds to write their researches on this field and implement them using SRDF.

--------------------
Introduction:
--------------------

In the last several years, the malware black market grows widely. The statistics shows that the number of new viruses increased from 300,000 viruses to millions and millions nowadays.

The complexity of malware attacks also increased from small amateur viruses to stuxnet, duqu and flame.

The malware field is searching for new technologies and researches, searching for united community can withstand against these attacks. And that’s why SRDF

The SRDF is not and will not be developed by one person or a team. It will be developed by a big community tries to share their knowledge and tools inside this Framework

SRDF still not finished … and it will not be finished as it’s a community based framework developed by the contributors. We just begin the idea.

The SRDF is divided into 2 parts: User-Mode and Kernel-Mode. And we will describe each one in the next section.

--------------------
The Features:
--------------------

Before talking about SRDF Design and structure, I want to give you what you will gain from SRDF and what it could add to your project.

--------------------------------------------------------------------
In User-Mode part, SRDF gives you many helpful tools … and they are:
--------------------------------------------------------------------

Assembler and Disassembler
x86 Emulator
Debugger
PE Analyzer
Process Analyzer (Loaded DLLs, Memory Maps … etc)
MD5, SSDeep and Wildlist Scanner (YARA)
API Hooker and Process Injection
Backend Database, XML Serializer
And many more

--------------------------------------------------------------------
In the Kernel-Mode part, it tries to make it easy to write your own filter device driver (not with WDF and callbacks) and gives an easy, object oriented (as much as we can) development framework with these features:
--------------------------------------------------------------------

Object-oriented and easy to use development framework
Easy IRP dispatching mechanism
SSDT Hooker
Layered Devices Filtering
TDI Firewall
File and Registry Manager
Kernel Mode easy to use internet sockets
Filesystem Filter

Still the Kernel-Mode in progress and many features will be added in the near future.

More About the Project: https://www.owasp.org/index.php/OWASP_Security_Research_and_Development_Framework

Facebook Page: http://www.facebook.com/SecDevelop

Mailing List: https://lists.owasp.org/mailman/listinfo/owasp_security_research_and_development_framework

JOIN US ... just mail me at: amr.thabetat<at>owasp.org
