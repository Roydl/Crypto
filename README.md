<p align="center"><a href="https://dotnet.microsoft.com/download/dotnet/5.0"><img src="https://img.shields.io/badge/core-%3E=%20v5.0-lightgrey.svg?style=flat&logo=.net&logoColor=white" alt="platform"></a> &nbsp; <a href="https://github.com/Roydl/Crypto/blob/master/LICENSE.txt"><img src="https://img.shields.io/github/license/Roydl/Crypto.svg?style=flat" alt="license"></a> &nbsp; <a href="https://www.nuget.org/packages/Roydl.Crypto"><img src="https://img.shields.io/badge/nuget-%20v1.0.2-lightgrey.svg?style=flat&logo=nuget&logoColor=white" alt="nuget"></a> &nbsp; <a href="https://github.com/Roydl/Crypto/archive/master.zip"><img src="https://img.shields.io/badge/download-source-yellow.svg?style=flat" alt="download"></a> &nbsp; <a href="https://www.si13n7.com"><img src="https://img.shields.io/website/https/www.si13n7.com.svg?style=flat&down_color=red&down_message=offline&up_color=limegreen&up_message=online&logo=data%3Aimage%2Fpng%3Bbase64%2CiVBORw0KGgoAAAANSUhEUgAAAA4AAAAOCAYAAAAfSC3RAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAEwSURBVDhPxZJNSgNBEIXnCp5AcCO4CmaTRRaKBhdCFkGCCKLgz2Y2RiQgCiqZzmi3CG4COj0X8ApewSt4Ba%2FQ9leZGpyVG8GComtq3qv3qmeS%2Fw9nikHMd5sVn3bqLx7zom1NcW8z%2F6G9CjoPm722rPEv45EJ21vD0O30AvX12IWDvTRsrPXrnjPlUYO0u3McVpZXhch5cnguZ7vVDWfpjRAZgPqc%2BIMEgKQe9Pfr0xn%2FBqZJjAUNQKilp5cC1gHYYz8Usc3OQsTz9HZWK5BMJwFDwrbWbuIXhfhg%2FDpWuE2mK5lEgQtiz4baU14u3V09i5peiipy6qVAxFWtZiflJiq8AAiIZx1CnxpStGmEpEHDZf4r2pUd%2BMjYxomoxJofo4L%2FHqyR57OF6vEvIkm%2BAYRc%2BWd4P97CAAAAAElFTkSuQmCC" alt="website"></a> &nbsp; <a href="https://www.si13n7.de"><img src="https://img.shields.io/website/https/www.si13n7.de.svg?style=flat&down_color=red&down_message=offline&label=mirror&up_color=limegreen&up_message=online&logo=data%3Aimage%2Fpng%3Bbase64%2CiVBORw0KGgoAAAANSUhEUgAAAA4AAAAOCAYAAAAfSC3RAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAEwSURBVDhPxZJNSgNBEIXnCp5AcCO4CmaTRRaKBhdCFkGCCKLgz2Y2RiQgCiqZzmi3CG4COj0X8ApewSt4Ba%2FQ9leZGpyVG8GComtq3qv3qmeS%2Fw9nikHMd5sVn3bqLx7zom1NcW8z%2F6G9CjoPm722rPEv45EJ21vD0O30AvX12IWDvTRsrPXrnjPlUYO0u3McVpZXhch5cnguZ7vVDWfpjRAZgPqc%2BIMEgKQe9Pfr0xn%2FBqZJjAUNQKilp5cC1gHYYz8Usc3OQsTz9HZWK5BMJwFDwrbWbuIXhfhg%2FDpWuE2mK5lEgQtiz4baU14u3V09i5peiipy6qVAxFWtZiflJiq8AAiIZx1CnxpStGmEpEHDZf4r2pUd%2BMjYxomoxJofo4L%2FHqyR57OF6vEvIkm%2BAYRc%2BWd4P97CAAAAAElFTkSuQmCC" alt="mirror"></a></p>

# Roydl.Crypto

The idea is to create a comfortable way to translate data. You can easily create instances of any type to translate  `Stream`, `byte[]` or `string` data. With the exception of `AES` encryption and decryption, extension methods are also provided for all types.

---


## Included `Binary-To-Text` algorithms:

| Name | Algorithm |
| ---- | ---- |
| Radix2 | Binary character set, such as `0` and `1` |
| Radix8 | Octal character set, such as `0-7` |
| RadixA | Decimal character set, such as `0-9` |
| RadixF | Hexadecimal character set, such as `0-9` and `a-f` |
| Base32 | Standard 32-character set, such as `A–Z`, `a–z` and `2–7` |
| Base64 | Standard 64-character set, such as `A–Z`, `a–z`, `0–9`, `+`, `/` and `=` |
| Base85 | Standard 85-character set, such as `A–Z`, `a–z`, `0–9` and <code>!&#35;$%&amp;()*+-;&lt;=&gt;?@^_&#96;{&#124;}~</code> |
| Base91 | Standard 91-character set, such as `A–Z`, `a–z`, `0–9`, and <code>!&#35;$%&amp;()*+,-.:;&lt;=&gt;?@[]^_&#96;{&#124;}~&quot;</code> |

### Extension methods:
```cs
// The `value` must be type `string` or `byte[]`, if `BinaryToTextEncoding` is
// not set, `Base64` is used by default.
string base85text = value.Encode(BinaryToTextEncoding.Base85);
byte[] original = value.Decode(BinaryToTextEncoding.Base85); // if `value` to decode is `byte[]`
string original = value.DecodeString(BinaryToTextEncoding.Base85); // if `value` to decode is `string`

// The `value` of type `string` can also be a file path, which is not
// recommended for large files. 
string base85text = value.EncodeFile(BinaryToTextEncoding.Base85);
byte[] original = value.DecodeFile(BinaryToTextEncoding.Base85);
```

---

## Included `Checksum` algorithms:

| Name | Algorithm |
| ---- | ---- |
| Adler32 | Default |
| CRC-16 | AUG-CCITT |
| CRC-32 | ISO-HDLC |
| CRC-64 | ECMA |
| MD5 | System.Security.Cryptography.MD5CryptoServiceProvider() |
| SHA-1 | System.Security.Cryptography.SHA1CryptoServiceProvider() |
| SHA-256 | System.Security.Cryptography.SHA256CryptoServiceProvider() |
| SHA-384 | System.Security.Cryptography.SHA384CryptoServiceProvider() |
| SHA-512 | System.Security.Cryptography.SHA512CryptoServiceProvider() |

### Extension methods:
```cs
// The `value` can be almost anything, even an entire type with many values,
// which is then serialized into a JSON byte sequence before being computed. 
string sha512hash = value.Encrypt(ChecksumAlgorithm.Sha512);
string crc32hash = value.Encrypt(ChecksumAlgorithm.Crc32);

// MD5 is used by default if `ChecksumAlgorithm` is not set.
string md5hash = value.Encrypt();

// The `EncryptRaw` extension method is CRC-32 only.
uint crc32raw = value.EncryptRaw();
```

---

## Other included algorithm:

| Name | Algorithm |
| ---- | ---- |
| AES | Rijndael `128` bit block size; optional: `128`, `192` or `256` bit key size, `cipher` and `padding` modes |
