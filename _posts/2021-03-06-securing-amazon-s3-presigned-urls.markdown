---
layout: post
title:  "Securing your Amazon AWS S3 presigned URLs, tips and tricks"
subtitle: "Security tips to consider while designing user's upload features using presigned URLs"
date:   2021-03-06 18:20:24 +0100
author: "santoru"
visible: 1
comments: true

---
# Abstract
With the advent of the cloud, [Amazon AWS S3](https://aws.amazon.com/s3/)
(Simple Storage Service) has become widely used in most companies to store
objects, files or more generally data in a persistent and easily accessible way.

AWS S3 buckets can be (and in fact, are) integrated in almost any modern
infrastructure: from mobile applications where the S3 bucket can be queried
directly, to web applications where it could be proxies behind a back end,
to micro-services that use them to store processed documents, logs, or other
data for both short term and long term storage.

If you use S3 in your infrastructure, you will probably find yourself in the
situation where you want to return a file from an S3 bucket to the user, or
where you need your user to safely upload a file into the S3 bucket. To make
this integration easier and safer, S3 provides the so-called
[presigned URLs](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ShareObjectPreSignedURL.html).

This blog post will briefly explain what a presigned URL is and will summarize
the security considerations and tips I ended up writing after several time
spent playing with them and threat modeling user's file upload features.

You will not find ready to copy-paste policy configuration for your S3 bucket
or detailed explanation on how to secure your bucket, what you will find
here is a list of good-to-know and good-to-remember considerations that you
should keep in mind if your goal is to use presigned URLs to store object into
an S3 bucket in a safe(r) way.

#### Disclaimer
This is the result of my experience with S3 buckets, not an absolute truth.
If you notice any error or inaccuracy [report it to me](mailto:{{ site.email }}),
I'll learn something new and I can make the article more accurate.

## Presigned URLs: What are these and some use cases
Before starting with the list of tips, let's briefly discuss what the general
use case for presigned URLs is in a generic modern environment.

Let's say you host some files on an S3 bucket and you need to expose these to
a user but you don't want to setup the bucket as open, also let's say you want
to keep some control on the access to these files, for example by limiting the
time-frame where the files can be accessed by the user.

Now let's say you create a feature that involves the user uploading a document
and that you want to store this file into an S3 bucket. 
How do you handle this in a secure way?



Here's were presigned URLs come in handy: AWS S3 provides an easy way to share
S3 objects by creating signed (with owner credentials) links to access them.
[Amazon's documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ShareObjectPreSignedURL.html)
explain this concept in a clear way:

> All objects by default are **private**. Only the object owner has permission
to access these objects. However, the object owner can **optionally share**
objects with others by creating a presigned URL, using their own security
credentials, to grant **time-limited permission** to download the objects.

So here's the deal, unless you configure your bucket differently (for example
to be read-accessible to everybody) your files are private but can be shared by
creating a time-limited permission in the form of a link, neat!

But how does a presigned URL look like? Let's go with an example:
```
https://yourbucket.s3.eu-west-1.amazonaws.com/yourfile.pdf?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=some-aws-credential-to-identify-the-signer&X-Amz-Date=timestamp-of-generation&X-Amz-Expires=validity-from-generation-timestamp&X-Amz-Signature=4709da5a980e6abc4ab7284c1b6aa9e624f388e08f6a7609e28e5041a43e5dad&X-Amz-SignedHeaders=host

```
or in a more user-friendly format:
```
https://yourbucket.s3.eu-west-1.amazonaws.com/pdf/yourfile.pdf ?
X-Amz-Algorithm     =   AWS4-HMAC-SHA256 &
X-Amz-Credential    =   some-aws-credential-to-identify-the-signer &
X-Amz-Date          =   timestamp-of-generation &
X-Amz-Expires       =   validity-from-generation-timestamp &
X-Amz-Signature     =   4709da5a980e6abc4ab7284c1b6aa9e624f388e08f6a7609e28e5041a43e5dad &
X-Amz-SignedHeaders =   host

```
Most of these parameters are configured or generated by using the AWS SDK
functionalities but how to create a presigned URL is not the goal of this
article. What it's important to remember is that S3 will try to compute the
same signature for the specified credentials, including into its calculation
the optional `SignedHeaders` parameter and checking if the signature is valid
and if the link is not expired yet.

Something else that is important to remember is that when you create a presigned
URL for an object (for both scenarios where you want to upload or download a file)
you **must provide to the SDK valid credentials** to generate a valid
signature. This means that the presigned URL will be authenticated to access the
resource "on behalf of" the credentials you used to generate it.

Said that, the ideal setup would usually be to have a dedicated back end service
with dedicated (and restricted) credentials to generate presigned URLs for
specific resources and returning these to the front end or to the client,
where can be directly used to **read** or **write** the "signed" resource (Fig. 1).

{% include image.html 
    url="img/s3/upload_scenario.png" 
    description="Figure 1 - A very simplified schema that shows how presigned URLs are used" 
%}


But let's go next with the recommendations, not sorted in any specific order.

## 1. Presigned URLs can be reused
Yes, these URLs are not one-shot and the only thing that can limit temporally
a presigned URL is the `X-AMZ-Expires` parameter: once the presigned URL is
generated, it will be valid for an unlimited amount of times before it expires.
This means that if you grant read access to an object in a bucket for 1 day,
anyone with the link can access that object for the whole day, multiple times.
This also means that if you grant write access via a presigned URL to a bucket
for 1 day, anyone with the URL could upload whatever file they want, any time 
they want.

## 2. Anyone can use a valid presigned URL
Just to make sure this is clear: if you generate a presigned URL anyone can use
this, the user generating this link could use it to _phish_ another user
and let them upload an arbitrary file.
So be sure you threat model properly your feature to avoid logic
vulnerabilities. If your service is generating a presigned URL valid for 10
minutes to upload a file, that URL can be used by anyone, unless you
validate the request in a different way; A solution could be adding an
additional signed header while building the presigned URL in a way that 
only allowed clients can perform the request (Check point #8).

## 3. Presigned URLs do not provide authentication
When your service returns a presigned URL to a user, the user will consume it
to read / upload an object directly from / into the S3 bucket. This means
that your service will not handle that file directly before it's uploaded.
This also means that your authentication layer will not usually be in place,
unless your s3 bucket has some authentication proxy in front of it.
In other words, presigned URLs only provide authorization to access a specific
object in a bucket (and eventually impose some restrictions to that access)
but the authentication is implicitly connected to the IAM role that
generates the presigned link. In your ideal setup this means that your service
will use its credentials to generate a presigned URL that the S3 bucket
will match to the service while checking the signature, not to the client.
If you want to provide authentication to the actual user consuming the link,
you need to implement this by yourself while generating the presigned link,
for example by storing the presigned link along with the user identifier that
requested it.

For file uploads, another solution could be to generate a random UUID as
filename for the object to be uploaded and store this UUID with the user
identifier on your database, otherwise you can append the user identifier
directly to the random UUID on the filename.

## 4. Do not give full access to the bucket to the service creating presigned URLs
If the task of your back end service is to only upload files into a bucket,
you probably don't need to configure an IAM role that is capable of reading
all the objects in the bucket or to delete them, and you probably don't
want this to happen too, so keep in mind to stick to the principle of least
privilege and only grant the necessary permissions when configuring the
IAM role.

Having your back-end service handling credentials that can do more than you want
is a big risk for your infrastructure security and your users: let's say you
configure your service to use bucket's owner credentials, what happen if the
keys get leaked or if a malicious actor can access them? You got this right,
they have full access to the bucket and to its content. Now let's say your
service is configured with an IAM role that can only read files under a specific
folder, you see the improvements? The attacker can still read uploaded
files, and this is still bad, but definitely better than having the attacker
deleting all the files, or replacing some with malicious ones.

Keep also in mind that credentials or keys shouldn't be hard coded,
there are several alternative to safely store secret and retrieve them
when needed, and AWS itself has also a specific service to do that, called
[AWS Secrets Manager](https://aws.amazon.com/secrets-manager/), so don't 
hard-code credentials and secret. 

## 5. Enable server access logging on your exposed S3 bucket
This is a generic recommendation that applies even if you don't use presigned
URL and should be followed for any S3 bucket, the explanation of this is clearly
reported on the [Server Logs](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html)
page from AWS:

> Server access logging provides detailed records for the requests that are
made to a bucket. Server access logs are useful for many applications.
For example, access log information can be useful in security and access 
audits. It can also help you learn about your customer base and understand
your Amazon S3 bill.

This is not enabled by default, as mentioned on the
[relevant web page](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-server-access-logging.html):

> By default, Amazon S3 doesn't collect server access logs.

## 6. Path traversal can be a thing, sanitize that filename
Or even better, use a random UUID.
Depending on your application's design, if the user can control the filename of
the file being uploaded, you could be exposed to some threats like path
traversal attacks, as shown
[here](https://hackerone.com/reports/94087) or
[here](https://hackerone.com/reports/254200). To avoid this, you should sanitize
that filename before using it to generate the presigned URL. Another good
solution would be to generate a random UUID and use that as a filename,
completely discarding the user controlled input.

## 7. Be careful with file-size, there's no built in functionality to limit it
With presigned URL, 
[you don't have an easy way to limit file size](https://github.com/aws/aws-sdk-net/issues/424)
, and this can be a problem. S3 has a cap of 5GB per request so you shouldn't
end up with a huge file on your disk but based on your file processing
algorithm and your expectation on the file size, 5GB could be a bit more
than you expect.

Presigned URLs do not allow to configure a max file size with an easy-to-set
parameter but there are some workaround to this, as you can see from #8 or #9.

According to your infrastructure design, this could even not be a problem (but
it's still good to keep this in mind).

## 8. Using signed headers, you can add a file's hash and avoid uncontrolled file uploads
As said before, once a presigned URL is generated, you don't have control over
who can upload a file, but you can mitigated this by generating a presigned URL
that checks for the file's md5 hash, how? By using `X-Amz-SignedHeaders`.

By specifying the `Content-MD5` header while generating the presigned URL, your
service can enforce the presigned URL to be valid only if the specified value
for this header is the same from the one specified, and the one received by the
user while uploading a file. This way you can generate a presigned URL for a
specific file, not for a generic one (Fig. 2).

{% include image.html 
    url="img/s3/upload_md5.png" 
    description="Figure 2 - Presigned URL generation by enforcing the md5 hash" 
%}

Keep in mind that this will not protect from a customer that want to upload
an arbitrary file, as the customer will be able to compute the hash and
request the presigned link for this file, but will protect from scenarios 
where the user wants to use a presigned link and let someone else uploading
an arbitrary files (for example in a phishing scenario).

You can use `SignedHeaders` also to enforce additional controls, for example on
file size by signing the `content-length` header.

## 9. You could use POST rather than PUT
Amazon's AWS S3 documentation
[mention that](https://docs.aws.amazon.com/AmazonS3/latest/userguide/PresignedUrlUploadObject.html):
> When you create a presigned URL, you must provide your security
credentials and then specify a bucket name, an object key,
an HTTP method (**PUT for uploading objects**), and an expiration date and time.
This is the default situation, but using PUT method you don't have some controls
that you could get with POST, why? Because of
[POST Policies](https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-HTTPPOSTConstructPolicy.html).

A POST Policy is a sequence of rules (called conditions) that must be met when
performing a POST request to an S3 bucket in order for this request to success.
You can configure these directly from the AWS console.

One benefit, over the others, of using a POST policy is that the
[list of conditions](https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-HTTPPOSTConstructPolicy.html#sigv4-PolicyConditions)
contains `content-length-range`, which can be used to easily solve the
consideration #7.

But can I still use PUT? 

It is still not clear to me what's the best solution is between POST and PUT, I
saw both used in productions and I think that depends a lot on the specific use
case: presigned URL uses PUT by default, and you don't need to write a policy,
but you loose flexibility. On the other hands, POST give you more control but
is less straightforward to implement in my opinion.
Amazon seems to suggest using POST policy,
[considering this article where they show an example of browser-based upload](https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-post-example.html).

## 10. Keep the expiration of the presigned URL low, especially for file write
This is self-explanatory, keep the presigned URL as short-lived as you can.
Most of the time, presigned URL are used to download a single file from a
bucket, and then are discarded. In most scenarios, your front end does not even
keep track of the link itself and, once the file is downloaded, is discarded.

For file upload the situation is similar: if your front end is taking care of
requesting the presigned link and uploading the file, this shouldn't take
long. If it's taking longer than expected, the presigned link could be requested
again. There's no need to keep an upload link valid for hours.

## 11. Don't forget to configure CORS
If your front end is a web application served in a browser, you must configure
CORS (Cross Origin Resource Sharing) otherwise your client's requests will fail
due to browser's protection. CORS is intended to protect your customers from
malicious website that could perform actions on behalf of the customer.

Even if your policies and permissions still apply when you configure
CORS, blocking unauthorized websites to perform cross-origin requests to your
bucket is a must do.

Via the CORS configuration panel you can configure your allowed domains on the
`AllowedOrigin` object. Keep in mind the principle of least privilege also when
configuring CORS: only white-list websites that you have control over.

If you want to know more about CORS and how to apply it, Amazon provides a
[great documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cors.html)
on the topic with lot of examples and I suggest you to read it.

If your front end is a mobile application, then CORS won't apply, as CORS is
enforced by browsers to avoid cross-origin and mobile applications are not
considered a web origin (and are not susceptible to attacks that leverage 
cross-origin requests). In this case you still want to ensure that websites 
can't access your bucket and you can do this by ensuring that your CORS is
enabled without any allowed origin or is disabled. If CORS is disabled,
browsers will not perform any request.

# Conclusion
With this blog post I hope that I gave you an idea about what to keep in mind
while designing a user upload feature with presigned URLs. As you can see,
depending on your threat model, the things to keep in mind can be different.

I'm sure there are other valid recommendations that you can suggest, as I don't
think I cover 100% of the things.

File uploads can be very dangerous functionalities and the risks involved are
multiple. Even if you follow these recommendation, you don't know if the file
being uploaded from a user is malicious or not, and processing it could have
unwanted results. That's why it is suggested to process untrusted files in a
restricted environment.

Finally, AWS provides lot of documentation on S3 and how to secure it further,
I suggest you to read
[this document](https://aws.amazon.com/premiumsupport/knowledge-center/secure-s3-resources/)
if you'd like to know more about how to secure files in S3 buckets.

If you enjoyed this post, you can
[follow me on Twitter](https://twitter.com/santoru_)
or
[check out my GitHub profile](https://github.com/santoru)

# References
- <a href="https://aws.amazon.com/s3/" target="_blank">Amazon AWS S3</a>
- <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/ShareObjectPreSignedURL.html" target="_blank">AWS Docs | Sharing an object with a presigned URL</a>
- <a href="https://aws.amazon.com/secrets-manager/" target="_blank">Amazon AWS Secret Manager</a>
- <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html" target="_blank">AWS Docs | Logging requests using server access logging</a>
- <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-server-access-logging.html" target="_blank">AWS Docs | Enabling Amazon S3 server access logging</a>
- <a href="https://hackerone.com/reports/94087" target="_blank">Arbitrary read on s3://shopify-delivery-app-storage/files</a>
- <a href="https://hackerone.com/reports/254200" target="_blank">Escaping images directory in S3 bucket when saving new avatar, using Path Traversal in filename</a>
- <a href="https://github.com/aws/aws-sdk-net/issues/424" target="_blank">Limit an upload filesize with a Pre-signed URL</a>
- <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/PresignedUrlUploadObject.html" target="_blank">AWS Docs | Uploading objects using presigned URLs</a>
- <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-HTTPPOSTConstructPolicy.html" target="_blank">AWS Docs | Creating a POST Policy</a>
- <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-HTTPPOSTConstructPolicy.html#sigv4-PolicyConditions" target="_blank">AWS Docs | Creating a POST Policy - Conditions</a>
- <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-post-example.html" target="_blank">AWS Docs | Example: Browser-Based Upload using HTTP POST (Using AWS Signature Version 4)</a>
- <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/cors.html" target="_blank">AWS Docs | Using cross-origin resource sharing (CORS)</a>
- <a href="https://aws.amazon.com/premiumsupport/knowledge-center/secure-s3-resources/" target="_blank">How can I secure the files in my Amazon S3 bucket?</a>
- <a href="https://twitter.com/santoru_" target="_blank">santoru_ | Twitter</a>
- <a href="https://github.com/santoru" target="_blank">santoru | GitHub</a>
