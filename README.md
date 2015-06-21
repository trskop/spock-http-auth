# HTTP Authentication Framework for Spock

[![Haskell Programming Language](https://img.shields.io/badge/language-Haskell-blue.svg)][Haskell.org]
[![BSD3 License](http://img.shields.io/badge/license-BSD3-brightgreen.svg)][tl;dr Legal: BSD3]

[![Build Status](https://travis-ci.org/trskop/spock-http-auth.svg)](https://travis-ci.org/trskop/spock-http-auth)


## Description

HTTP authentication is not limited to those defined by the standard:

* [HTTP Basic Authentication][Wikipedia: Basic access authentication]
* [HTTP Digest Authentication][Wikipedia: Digest access authentication]

This library provides building block for developers to create their own
authentication schemes on top of standard HTTP vocabulary.

Examples of alternative HTTP authentication schemes:

* [Amazon S3: Signing and Authenticating REST Requests][]
* [NTLM Authentication Scheme for HTTP][]


## License

Revised BSD License, also known as 3-clause BSD license. For more
information see e.g. [tl;drLegal: BSD 3-Clause License (Revised)
][tl;dr Legal: BSD3] and for full license text read [LICENSE
](https://github.com/trskop/spock-http-auth/blob/master/LICENSE) file.


## Contributions

Contributions, pull requests and bug reports are welcome! Please don't be
afraid to contact author using GitHub or by e-mail.


[Haskell.org]:
  http://www.haskell.org
  "The Haskell Programming Language"
[tl;dr Legal: BSD3]:
  https://tldrlegal.com/license/bsd-3-clause-license-%28revised%29
  "BSD 3-Clause License (Revised)"
[Wikipedia: Basic access authentication]:
  https://en.wikipedia.org/wiki/Basic_access_authentication
  "Wikipedia: Basic access authentication"
[Wikipedia: Digest access authentication]:
  https://en.wikipedia.org/wiki/Digest_access_authentication
  "Wikipedia: Digest access authentication"
[Amazon S3: Signing and Authenticating REST Requests]:
  http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html
  "Amazon S3: Signing and Authenticating REST Requests"
[NTLM Authentication Scheme for HTTP]:
  http://www.innovation.ch/personal/ronald/ntlm.html
  "NTLM Authentication Scheme for HTTP"
