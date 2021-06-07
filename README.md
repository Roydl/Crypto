<p align="center">
<a href="https://dotnet.microsoft.com/download/dotnet/5.0" rel="nofollow"><img src="https://img.shields.io/badge/core-v3.1%20or%20higher-lightgrey?style=for-the-badge&logo=dot-net&logoColor=white" title=".NET Core v3.1 LTS or higher" alt=".NET Core"></a>
<a href="https://github.com/Roydl/Crypto/actions"><img src="https://img.shields.io/badge/cross%E2%80%93platform-%e2%9c%94-blue?style=for-the-badge&logo=linux&logoColor=silver" title="Automatically tested with Windows 10 &amp; Ubuntu 20.04 LTS" alt="Cross-platform"></a>
<a href="https://github.com/Roydl/Crypto/blob/master/LICENSE.txt"><img src="https://img.shields.io/github/license/Roydl/Crypto?style=for-the-badge" title="Read the license terms" alt="License"></a>
</p>
<p align="center">
<a href="https://github.com/Roydl/Crypto/actions/workflows/dotnet.yml"><img src="https://img.shields.io/github/workflow/status/Roydl/Crypto/build%2Btest?style=for-the-badge&label=build%2Btest&logo=github&logoColor=silver" title="Check the last workflow results" alt="Build+Test"></a>
<a href="https://github.com/Roydl/Crypto/commits/master"><img src="https://img.shields.io/github/last-commit/Roydl/Crypto?style=for-the-badge&logo=github&logoColor=silver" title="Check the last commits" alt="Commits"></a>
<a href="https://github.com/Roydl/Crypto/archive/refs/heads/master.zip"><img src="https://img.shields.io/badge/download-source-important?style=for-the-badge&logo=github&logoColor=silver" title="Start downloading the &apos;master.zip&apos; file" alt="Source"></a>
</p>
<p align="center">
<a href="https://www.nuget.org/packages/Roydl.Crypto"><img src="https://img.shields.io/nuget/v/Roydl.Crypto?style=for-the-badge&logo=nuget&logoColor=silver&label=nuget" title="Check out the NuGet package page" alt="NuGet"></a>
<a href="https://www.nuget.org/packages/Roydl.Crypto"><img src="https://img.shields.io/nuget/dt/Roydl.Crypto?logo=nuget&logoColor=silver&style=for-the-badge" title="Check out the NuGet package page" alt="NuGet"></a>
<a href="https://www.si13n7.com"><img src="https://img.shields.io/website/https/www.si13n7.com?style=for-the-badge&down_color=critical&down_message=down&up_color=success&up_message=up&logo=data%3Aimage%2Fpng%3Bbase64%2CiVBORw0KGgoAAAANSUhEUgAAAA4AAAAOCAYAAAAfSC3RAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAEwSURBVDhPxZJNSgNBEIXnCp5AcCO4CmaTRRaKBhdCFkGCCKLgz2Y2RiQgCiqZzmi3CG4COj0X8ApewSt4Ba%2FQ9leZGpyVG8GComtq3qv3qmeS%2Fw9nikHMd5sVn3bqLx7zom1NcW8z%2F6G9CjoPm722rPEv45EJ21vD0O30AvX12IWDvTRsrPXrnjPlUYO0u3McVpZXhch5cnguZ7vVDWfpjRAZgPqc%2BIMEgKQe9Pfr0xn%2FBqZJjAUNQKilp5cC1gHYYz8Usc3OQsTz9HZWK5BMJwFDwrbWbuIXhfhg%2FDpWuE2mK5lEgQtiz4baU14u3V09i5peiipy6qVAxFWtZiflJiq8AAiIZx1CnxpStGmEpEHDZf4r2pUd%2BMjYxomoxJofo4L%2FHqyR57OF6vEvIkm%2BAYRc%2BWd4P97CAAAAAElFTkSuQmCC" title="Visit the developer&apos;s website" alt="Website"></a>
<a href="https://www.si13n7.de"><img src="https://img.shields.io/website/https/www.si13n7.de?style=for-the-badge&down_color=critical&down_message=down&label=mirror&up_color=success&up_message=up&logo=data%3Aimage%2Fpng%3Bbase64%2CiVBORw0KGgoAAAANSUhEUgAAAA4AAAAOCAYAAAAfSC3RAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAEwSURBVDhPxZJNSgNBEIXnCp5AcCO4CmaTRRaKBhdCFkGCCKLgz2Y2RiQgCiqZzmi3CG4COj0X8ApewSt4Ba%2FQ9leZGpyVG8GComtq3qv3qmeS%2Fw9nikHMd5sVn3bqLx7zom1NcW8z%2F6G9CjoPm722rPEv45EJ21vD0O30AvX12IWDvTRsrPXrnjPlUYO0u3McVpZXhch5cnguZ7vVDWfpjRAZgPqc%2BIMEgKQe9Pfr0xn%2FBqZJjAUNQKilp5cC1gHYYz8Usc3OQsTz9HZWK5BMJwFDwrbWbuIXhfhg%2FDpWuE2mK5lEgQtiz4baU14u3V09i5peiipy6qVAxFWtZiflJiq8AAiIZx1CnxpStGmEpEHDZf4r2pUd%2BMjYxomoxJofo4L%2FHqyR57OF6vEvIkm%2BAYRc%2BWd4P97CAAAAAElFTkSuQmCC" title="Visit the developer&apos;s mirror website" alt="Mirror"></a>
</p>


# Roydl.Crypto

The idea was to create a handy way to hash and encrypt data, which can be used in any situation.

### Checksum Algorithms:

| Name | Hash Size | Algorithm | Type |
| ---- | ---- | ---- | ---- |
| Adler-32 | 32-bit | Standard | [Cyclic](https://en.wikipedia.org/wiki/Cyclic_code) |
| CRC | 8-bit to 82-bit (no limit for custom) | Choose from [88 presets](https://github.com/Roydl/Crypto/wiki/1.-Checksum-Algorithms) or create your own | [Cyclic](https://en.wikipedia.org/wiki/Cyclic_code) |
| MD5 | 128-bit | Built-in + HMAC keyed-hash support | [Cryptographic](https://en.wikipedia.org/wiki/Cryptographic_hash_function) |
| SHA-1 | 160-bit | Built-in + HMAC keyed-hash support | [Cryptographic](https://en.wikipedia.org/wiki/Cryptographic_hash_function) |
| SHA-2 | 256-bit to 512-bit | Built-in + HMAC keyed-hash support | [Cryptographic](https://en.wikipedia.org/wiki/Cryptographic_hash_function) |

#### Usage:

The `GetChecksum` extension method retrieves a **string** representation of the computed hash.

The **value** can be almost anything. No matter if it is **bool**, **sbyte**, **byte**, **short**, **ushort**, **char**, **int**, **uint**, **long**, **ulong**, **Half**, **float**, **double**, **decimal**, **Enum**, **IntPtr**, **UIntPtr**, **Vector{T}**, **Vector2**, **Vector3**, **Vector4**, **Matrix3x2**, **Matrix4x4**, **Plane**, **Quaternion**, **Complex**, **BigInteger**, **DateTime**, **DateTimeOffset**, **TimeSpan**, **Guid**, **Rune**, **Stream**, **StreamReader**, **FileInfo**, any **IEnumerable{T}** **byte** sequence, i.e. **Array**, or any **IEnumerable{T}** **char** sequence, i.e. **string**.

Not every type makes sense, but is supported anyway.

```cs
string hash = value.GetChecksum(ChecksumAlgo.Sha1);
Console.WriteLine(hash);

// Output:
// 12a5ba5baa1664f73e6279f23354bd90c8981a81
```

However, a **string** containing a file path has an additional method.

```cs
string hash = value.GetFileChecksum(); // SHA-256 is used when `ChecksumAlgo` is undefined
```

The `GetCipher` extension method retrieves an **unsigned 64-bit integer** representation of the computed hash. It follows the same rules outlined earlier. This can be useful with cyclic computed hashes.
```cs
ulong hash = value.GetCipher(ChecksumAlgo.Crc64);
```

Note that `HMAC` keyed-hashing is only supported for cryptographic algorithms via instances by setting a secret key.

```cs
Sha512 instance = new Sha512()
{
    SecretKey = new byte[128] { /* some bytes */ }
};
```

The `Encrypt` methods uses the secret key until `DestroySecretKey` or `Dispose` is called.

```cs
instance.Encrypt(value);
```

An instances provides a computed hash in several variants.

```cs
ReadOnlyMemory<byte> rawHash = instance.RawHash;
BigInteger cipher = instance.HashNumber; // The type depends on the hash size in bits, e.g. CRC-32 is `UInt32`
string lowercase = instance.Hash;
string uppercase = instance.ToString(true);
```

Casting is also supported to get a hash.

```cs
byte[] copyOfRawHash = (byte[])instance;
ulong cipher = (ulong)instance; // Numeric conversions are unchecked
string lowercase = (string)instance;
```

Instances also provide equality operators.

```cs
bool equ = (instance1 == instance2);
bool neq = (instance1 != instance2);
```

#### CRC customization:

If you need a different CRC algorithm, you can easily create your own variation.

This is an example for `CRC-32/POSIX`, but it should support many others from 8-bit to almost infinite bits.

```cs
const int width = 32;
const uint check = 0x765e7680u;
const uint poly = 0x04c11db7u;
const uint init = 0x00000000u;
const bool refIn = false;
const bool refOut = false;
const uint xorOut = 0xffffffffu;
const uint mask = 0xffffffffu;
const bool skipValidation = false;
```

Sets a new `CrcConfig` with the constants from above. The data are automatically validated with the given check.

```cs
var cfg = new CrcConfig32(width, check, poly, init, refIn, refOut, xorOut, mask, skipValidation);
```

Compute the hash directly via the configuration structure.

```cs
cfg.ComputeHash(stream, out uint cipher);
```

Or load it into the CRC class which has more features, and compute the hash code from there.

The **value** can be from type **Stream**, **byte[]**, **string**, **FileInfo**, or a **string** containing a file path.

```cs
var crc = new Crc<uint>(config);
crc.Encrypt(value);
```

As mentioned earlier, instances offer computed hashes in several variants. It follows the same rules that have already been explained above.

```cs
ReadOnlyMemory<byte> rawHash = crc.RawHash;
uint cipher = crc.HashNumber;
string lowercase = crc.Hash;
```

Check out the [CRC configuration manager](https://github.com/Roydl/Crypto/blob/master/src/Checksum/CrcConfigManager.cs) to see more examples.

---


### Other included algorithm:

| Name | Algorithm |
| ---- | ---- |
| Rijndael | `128` bit block size; optional: `128`, `192` or `256` bit key size, `cipher` and `padding` modes |


#### Usage:
```cs
byte[] password = new byte[] { /* some bytes */ };
byte[] salt = new byte[] { /* some bytes */ };
using var aes = new Rijndael(password, salt, 1000, SymmetricKeySize.Large);

byte[] encryptedBytes = aes.EncryptBytes(new byte[] { /* some bytes */ });
byte[] encryptedFile = aes.EncryptFile("C:\\FileToEncrypt.example");
aes.EncryptFile("C:\\FileToEncrypt.example", "C:\\EncryptedFile.example");

aes.EncryptStream(streamToEncrypt, encryptedStream);

byte[] decryptedBytes = aes.DecryptBytes(new byte[] { /* some bytes */ });
byte[] decryptedFile = aes.DecryptFile("C:\\Some\\File.source");
aes.DecryptFile("C:\\FileToDecrypt.example", "C:\\DecryptedFile.example");

aes.DecryptStream(streamToDecrypt, decryptedStream);
```

---


## Would you like to help?

- [Star this Project](https://github.com/Roydl/Crypto/stargazers) :star: and show me that this project interests you :hugs:
- [Open an Issue](https://github.com/Roydl/Crypto/issues/new) :coffee: to give me your feedback and tell me your ideas and wishes for the future :sunglasses:
- [Open a Ticket](https://www.si13n7.com/?page=contact) :mailbox: if you don't have a GitHub account, you can contact me directly on my website :wink:
- [Donate by PayPal](https://paypal.me/si13n7/) :money_with_wings: to buy me some cakes :cake:

_Please note that I cannot fix bugs that are unknown to me. So do yourself and me the favor and get in touch with me._ :face_with_head_bandage: