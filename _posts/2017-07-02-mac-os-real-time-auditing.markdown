---
layout: post
title:  "Real-time auditing on macOS with OpenBSM"
subtitle: "developing an application to monitor file system accesses and activities for every application"
date:   2017-07-02 21:05:24 +0100
author: "santoru"
visible: 1
comments: true

---

* table of context
{:toc}

## Introduction
Goal of this blog post is to explain how to use OpenBSM library to perform live audit on macOS to detect which files are open and by who.
Everyday we install some program, or application, on our computer and they can basically have access to the most of files.
Real-time auditing can be useful for a lot of reasons: maybe you're just curious to see which files are opened by some applications or if some malicious process are reading your personal documents, or maybe opening your photos. Maybe you are not curious but you just want to detect possible ransom-ware activity to stop them.<br/>
The scenarios are infinite.<br/>
Another common scenario is that you can use real-time auditing to build and run your personal Host-Based IDS by checking  modifications and accesses to sensible files.

In this blog post I will just explain how this auditing is possible thanks to OpenBSM, giving the reader some others resources for further "investigation" and publishing a small proof-of-concept of a basic implementation.

If you spot a mistake, I'll be happy to fix it, just send an [email to me](mailto:{{ site.email }}).


## OpenBSM
According to the Trusted BSD project, OpenBSM is an open-source implementation of Sun's BSM (Basic Security Module) event auditing file format and API originally created for Apple Computer by McAfee Research.

This implementation provides a set of system calls and library interfaces for **managing audit records** but includes also some command line tools.

As we can see from the configuration files located in <span class="mon">/etc/security</span>, by default macOS use two flags, <span class="mon">lo</span> and <span class="mon">aa</span>, to logs Login/Logout (lo) and Authorization/Authentication (aa) events on the <span class="mon">**/var/audit/**</span> directory.

<pre class="highlight">
$ cat /etc/security/audit_control

#
# $P4: //depot/projects/trustedbsd/openbsm/etc/audit_control#8 $
#
dir:/var/audit
<b>flags:lo,aa</b>
minfree:5
naflags:lo,aa
policy:cnt,argv
filesz:2M
expire-after:10M
superuser-set-sflags-mask:has_authenticated,has_console_access
superuser-clear-sflags-mask:has_authenticated,has_console_access
member-set-sflags-mask:
member-clear-sflags-mask:has_authenticated
</pre>

We can have some information about these flags, and about all available flags, from another file located on the same directory:

<pre class="highlight">
$ cat /etc/security/audit_class

#
# $P4: //depot/projects/trustedbsd/openbsm/etc/audit_class#6 $
#
0x00000000:no:invalid class
0x00000001:fr:file read
0x00000002:fw:file write
0x00000004:fa:file attribute access
0x00000008:fm:file attribute modify
0x00000010:fc:file create
0x00000020:fd:file delete
0x00000040:cl:file close
0x00000080:pc:process
0x00000100:nt:network
0x00000200:ip:ipc
0x00000400:na:non attributable
0x00000800:ad:administrative
<b>0x00001000:lo:login_logout
0x00002000:aa:authentication and authorization</b>
0x00004000:ap:application
0x20000000:io:ioctl
0x40000000:ex:exec
0x80000000:ot:miscellaneous
0xffffffff:all:all flags set
</pre>


Since we want to monitor which files are accessed by a process, we can build our own audit program using the functions provided from OpenBSM and log, or display, only relevant information.
To audit only some information we can then specify one or more of the flags above and, for example, if we want to log which files are open to be read, we can use the flag **"fr"** identified by the value **0x00000001**.

The Basic Security Module Library provides some functions to read these events and automatically parse them.
In details, we have 4 functions to manipulate and interact with events:
#### au_read_rec()

{% highlight c %}
int au_read_rec(FILE *fp, u_char **buf);
{% endhighlight %}
This function let us read an event record from a file descriptor and put the content in the buffer <span class="mon">buf</span> passed as parameter (which **must** be freed after use).
The function return the number of bytes read.

#### au_fetch_tok()

{% highlight c %}
int au_fetch_tok(tokenstr_t *tok, u_char *buf, int len);
{% endhighlight %}
The buffer obtained from <span class="mon">au_read_rec</span> contains tokens, every token is a struct with different information, according to the token id.
The first token of the buffer is always a <span class="mon">AUT_HEADER\*</span> token: it contains a field that indicate which kind of event is on the buffer. The next tokens contains information about the path of the process that raised the event, the path of the file interested by the event and other information like the user, the timestamp...
To read the buffer with the record inside we have to fetch every token on it sequentially, using the <span class="mon">au_fetch_tok</span>

#### au_print_tok()

{% highlight c %}
void au_print_tok(FILE *outfp, tokenstr_t *tok, char *del, char raw, char sfrm);
{% endhighlight %}
Now that we have a token, we can print it on a  file descriptor.

#### au_print_flags_tok()

{% highlight c %}
void au_print_flags_tok(FILE *outfp, tokenstr_t *tok, char *del, int oflags);
{% endhighlight %}
Another function to print token in a fancy way is to use <span class="mon">au_print_flags_tok</span> that accepts an additional parameter to specify different output formats (XML, raw, short..).

A typical use of these functions could be:
- Open a file (usually an audit pipe) with <span class="mon">fopen()</span> and print records on a buffer from the file by calling <span class="mon">au_read_rec()</span>.
- Read each token for each record through calls to <span class="mon">au_fetch_tok()</span> on the buffer
- Invoke <span class="mon">au_print_flags_tok()</span> to print each token to an output stream such as stdout.
- Free the buffer
- Close the opened file


There is only one problem I found while parsing these events with the functions provided: <span class="mon">au_print_tok()</span> and <span class="mon">au_print_flags_tok()</span> take as input a token from <span class="mon">au_fetch_tok()</span> and there is no way to parse or filter it, to have a nicer and more descriptive output of the token.
My solution was to bypass the two functions and manually parse the token to get only the most interesting properties. But how this tokens are made?
As said before, every event is made of some tokens. A token is just a C struct that contains some information according to the ID of the token.
A read event, for example, has 3 main tokens: <span class="mon">AUT_HEADER</span> , <span class="mon">AUT_SUBJECT</span> and <span class="mon">AUT_PATH</span>.<br/>
<span class="mon">AUT_HEADER</span> contains information about the event. In a read event, it display that the event is actually a file read (fr).<br/>
<span class="mon">AUT_SUBJECT</span> define which process raised this event while <span class="mon">AUT_PATH</span> specify which path was read by the <span class="mon">AUT_SUBJECT</span>.

We can manually parse the struct to print only useful information.

## The auditpipe
Now that we know how to read events we need to know from where we can take real-time events.
The solution is to use a specific device called <i>auditpipe</i> and located in <i>/dev/auditpipe</i>.

The auditpipe is a pseudo-device for live audit event tracking that can be opened as a file and used with the 4 functions above to read and parse our real-time events.

In order to use the auditpipe we need to configure it with <span class="mon">ioctl</span> system calls to set up which events we want to get from the pipe.<br />

### filewatcher - a simple auditing utility for macOS
I wrote a small utility to monitor file or process activities using the <i>auditpipe</i> and the functions I explained.<br/>
You can find it <a href="https://github.com/santoru/filewatcher" target="_blank">directly on GitHub</a><br/>
To configure the <i>auditpipe</i> I used an example found <a href="https://github.com/ashish-gehani/SPADE/blob/master/src/spade/reporter/spadeOpenBSM.c" target="_blank">here</a>.<br/> To parse the token's structure I used the open source code from <a href="https://github.com/openbsm/bsmtrace/blob/master/bsm.c" target="_blank">OpenBSM</a>.<br/>
The code is still pretty messy but it works!
The options are not so much at the moment, but my goal is to improve it to have a fully-working auditing tool.
At the moment it is possible to specify which process or which file to monitor.
By default, only some events are displayed, like **open/read/write/close**. Anyway, it's possible to display all events thanks to an option. Check the help message!<br/>
It's also possible, for now, to enable debug message logging into a file.

#### Installation
At the moment, There is only a line of code inside the <i>Makefile</i> to compile the tool, so you can just <span class="mon">make</span> and it will compile inside the <i>bin</i> folder.<br/>
If you want to manually compile it, you need to include the bsm library:
```bash
$ gcc -lbsm filewatcher.c lib/*.c -o bin/filewatcher
```


#### Usage
<pre class="highlight">
$ sudo ./bin/filewatcher -h
filewatcher - a simple auditing utility for macOS

Usage: ./bin/filewatcher [OPTIONS]
  -f, --file                 Set a file to filter
  -p, --process              Set a process name to filter
  -a, --all                  Display all events (By default only basic events like open/read/write are displayed)
  -d, --debug                Enable debugging messages to be saved into a file
  -h, --help                 Print this help and exit
</pre>

{% include image.html 
    url="img/filewatcher/screenshotsmall.png" 
    description="Figure 1 - An example of the output" 
%}


## References
- <a href="https://github.com/santoru/filewatcher" target="_blank">filewatcher</a>
- <a href="http://www.trustedbsd.org/" target="_blank">TrustedBSD</a>
- <a href="https://github.com/openbsm/openbsm" target="_blank">OpenBSM - GitHub</a>
- <a href="https://www.freebsd.org/cgi/man.cgi?query=auditpipe" target="_blank">Auditpipe ioctls</a>
- <a href="https://objective-see.com/blog/blog_0x0F.html" target="_blank">Towards Generic Ransomware Detection</a>
