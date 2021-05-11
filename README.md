<p align="center">
<a href="https://dotnet.microsoft.com/download/dotnet/5.0" rel="nofollow"><img src="https://img.shields.io/badge/core-v3.1%20%7C%20v5.0-lightgrey.svg?style=flat&amp;logo=.net&amp;logoColor=white" alt="Platform"></a>
<a href="https://github.com/Roydl/Crypto/actions/workflows/dotnet.yml"><img src="https://github.com/Roydl/Crypto/actions/workflows/dotnet.yml/badge.svg" alt="Build"></a>
<a href="https://github.com/Roydl/Crypto/commits/master"><img src="https://img.shields.io/github/last-commit/Roydl/Crypto.svg?style=flat&amp;logo=github&amp;logoColor=white" alt="Commits"></a>
<a href="https://github.com/Roydl/Crypto/blob/master/LICENSE.txt"><img src="https://img.shields.io/github/license/Roydl/Crypto.svg?style=flat" alt="License"></a>
</p>
<p align="center">
<a href="https://www.nuget.org/packages/Roydl.Crypto" rel="nofollow"><img src="https://img.shields.io/github/tag/Roydl/Crypto.svg?style=flat&amp;logo=nuget&amp;logoColor=white&amp;label=nuget" alt="NuGet"></a>
<a href="https://github.com/Roydl/Crypto/archive/master.zip"><img src="https://img.shields.io/badge/download-source-yellow.svg?style=flat" alt="Source"></a>
<a href="https://www.si13n7.com" rel="nofollow"><img src="https://img.shields.io/website/https/www.si13n7.com.svg?style=flat&amp;down_color=red&amp;down_message=offline&amp;up_color=limegreen&amp;up_message=online&amp;logo=data%3Aimage%2Fpng%3Bbase64%2CiVBORw0KGgoAAAANSUhEUgAAAA4AAAAOCAYAAAAfSC3RAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAEwSURBVDhPxZJNSgNBEIXnCp5AcCO4CmaTRRaKBhdCFkGCCKLgz2Y2RiQgCiqZzmi3CG4COj0X8ApewSt4Ba%2FQ9leZGpyVG8GComtq3qv3qmeS%2Fw9nikHMd5sVn3bqLx7zom1NcW8z%2F6G9CjoPm722rPEv45EJ21vD0O30AvX12IWDvTRsrPXrnjPlUYO0u3McVpZXhch5cnguZ7vVDWfpjRAZgPqc%2BIMEgKQe9Pfr0xn%2FBqZJjAUNQKilp5cC1gHYYz8Usc3OQsTz9HZWK5BMJwFDwrbWbuIXhfhg%2FDpWuE2mK5lEgQtiz4baU14u3V09i5peiipy6qVAxFWtZiflJiq8AAiIZx1CnxpStGmEpEHDZf4r2pUd%2BMjYxomoxJofo4L%2FHqyR57OF6vEvIkm%2BAYRc%2BWd4P97CAAAAAElFTkSuQmCC" alt="Website"></a>
<a href="https://www.si13n7.de" rel="nofollow"><img src="https://img.shields.io/website/https/www.si13n7.de.svg?style=flat&amp;down_color=red&amp;down_message=offline&amp;label=mirror&amp;up_color=limegreen&amp;up_message=online&amp;logo=data%3Aimage%2Fpng%3Bbase64%2CiVBORw0KGgoAAAANSUhEUgAAAA4AAAAOCAYAAAAfSC3RAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAEwSURBVDhPxZJNSgNBEIXnCp5AcCO4CmaTRRaKBhdCFkGCCKLgz2Y2RiQgCiqZzmi3CG4COj0X8ApewSt4Ba%2FQ9leZGpyVG8GComtq3qv3qmeS%2Fw9nikHMd5sVn3bqLx7zom1NcW8z%2F6G9CjoPm722rPEv45EJ21vD0O30AvX12IWDvTRsrPXrnjPlUYO0u3McVpZXhch5cnguZ7vVDWfpjRAZgPqc%2BIMEgKQe9Pfr0xn%2FBqZJjAUNQKilp5cC1gHYYz8Usc3OQsTz9HZWK5BMJwFDwrbWbuIXhfhg%2FDpWuE2mK5lEgQtiz4baU14u3V09i5peiipy6qVAxFWtZiflJiq8AAiIZx1CnxpStGmEpEHDZf4r2pUd%2BMjYxomoxJofo4L%2FHqyR57OF6vEvIkm%2BAYRc%2BWd4P97CAAAAAElFTkSuQmCC" alt="Mirror"></a>
</p>


# Roydl.Crypto

The idea was to create a handy way to hash and encrypt data.

You can easily create instances of any type to translate `Stream`, `byte[]` or `string` data. With the exception of `Rijndael` encryption and decryption, extension methods are also provided for all types.


### Checksum Encryption:

| Name | Hash Size | Algorithm |
| ---- | ---- | ---- |
| Adler32 | 32 | Standard |
| CRC16 | 16 | AUG-CCITT |
| CRC32 | 32 | Standard |
| CRC64 | 64 | ECMA |
| MD5 | 128 | Standard |
| SHA1 | 160 | Standard |
| SHA256 | 256 | SHA-2 Standard |
| SHA384 | 384 | SHA-2 Standard |
| SHA512 | 512 | SHA-2 Standard |

#### Checksum extension methods:
```cs
using Roydl.Crypto;

// The `value` can be almost anything, even an entire type with many values,
// which is then serialized into a JSON byte sequence before being computed. 
string md5hash = value.Encrypt(ChecksumAlgo.Md5);

// SHA-256 is used by default if `ChecksumAlgo` is not set.
string sha256hash = value.Encrypt();

// The `EncryptRaw` extension method is CRC-32 only.
uint crc32raw = value.EncryptRaw();
```

---

### Other included algorithm:

| Name | Algorithm |
| ---- | ---- |
| Rijndael | `128` bit block size; optional: `128`, `192` or `256` bit key size, `cipher` and `padding` modes |

---


## Would you like to help?

- [Star this Project](https://github.com/Roydl/Crypto/stargazers) :star: and show me that this project interests you :hugs:
- [Open an Issue](https://github.com/Roydl/Crypto/issues/new) :coffee: to give me your feedback and tell me your ideas and wishes for the future :sunglasses:
- [Open a Ticket](https://support.si13n7.de/) :mailbox: if you don't have a GitHub account, you can contact me directly on my website :wink:
- [Donate by PayPal](http://donate.si13n7.com/) :money_with_wings: to buy me some cookies :cookie:

