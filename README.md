<p align="center">
<a href="https://dotnet.microsoft.com/download/dotnet/5.0" rel="nofollow"><img src="https://img.shields.io/badge/core-v3.1%20%7C%20v5.0-lightgrey.svg?style=flat&amp;logo=.net&amp;logoColor=white" alt="Platform"></a>
<a href="https://github.com/Roydl/Crypto/actions/workflows/dotnet.yml"><img src="https://github.com/Roydl/Crypto/actions/workflows/dotnet.yml/badge.svg" alt="Build"></a>
<a href="https://github.com/Roydl/Crypto/commits/master"><img src="https://img.shields.io/github/last-commit/Roydl/Crypto.svg?style=flat&amp;logo=github&amp;logoColor=white" alt="Commits"></a>
<a href="https://github.com/Roydl/Crypto/blob/master/LICENSE.txt"><img src="https://img.shields.io/github/license/Roydl/Crypto.svg?style=flat" alt="License"></a>
</p>
<p align="center">
<a href="https://www.nuget.org/packages/Roydl.Crypto" rel="nofollow"><img src="https://img.shields.io/nuget/v/Roydl.Crypto.svg?style=flat&amp;logo=nuget&amp;logoColor=white&amp;label=nuget" alt="NuGet"></a>
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

#### Usage:
```cs
// The `value` can be almost anything, even an entire type with many values,
// which is then serialized into a JSON byte sequence before being hashed.
string hash1 = value.Encrypt(ChecksumAlgo.Md5);

// SHA-256 is used by default if `ChecksumAlgo` is not set.
string hash2 = value.Encrypt();

// The file encryption has an additional method, where `value` must be a
// `string` with a valid file path.
string hash3 = value.EncryptFile();

// The `EncryptRaw` extension method retrieves an unsigned 64-bit integer
// representation of the computed hash. It follows the same rules outlined
// earlier.
// It can be helpful to compare types that are normally not comparable.
ulong hash3 = value.EncryptRaw(ChecksumAlgo.Crc64);

// Instances are also supported. However, the `value` must be a stream,
// byte sequence, or string.
Sha1 instance1 = new Sha1(value);

// Files can be encrypted with an extra boolean when `value` is a string,
Crc32 instance2 = new Crc32(value, true);

// You can also initialize an instance without parameters.
Sha512 instance3 = new Sha512();

// And use the encryption methods later as described earlier.
instance3.Encrypt(value);
instance3.EncryptFile(value);

// The last encrypted data will be stored in some fields.
string hash = instance3.Hash;
byte[] raw = instance3.RawHash;

// This corresponds to the `EncryptRaw` extension method. This field came
// later, so the name is different. `EncryptRaw` was first created
// exclusively for CRC. Only the CRC `RawHash` was an integral value, but
// it is now always a sequence of bytes and this field was added to support
// all other types as well.
long num = instance3.HashNumber;

// The last thing you need to know is that instances have equality operators.
bool equ = (instance1 == instance3);
bool neq = (instance1 != instance3);
```

#### CRC customization:

If you need a different CRC algorithm, you can easily create your own variations. This is an example for `CRC-32/POSIX`, but it should support many others between 8 and 64 bits.

```cs
public sealed class Crc32Posix : ChecksumAlgorithm<Crc32Posix>
{
    // Sets a new `CrcConfig` with bits, polynomial, seed, normal compution,
    // and reversed bits of final hash.
    private static readonly CrcConfig<uint> Current = new(32, 0x4c11db7u, 0u, false, true);

    // At least one constructor is required because `base (bits)` has to
    // be called.
    public Crc32Posix() : base(32) { }

    // All other constructors require the call to `this()`.
    public Crc32(Stream stream) : this() =>
        Encrypt(stream);

    // Lets `CrcConfig` struct do the job. This method is the only one
    // that needs to be overwritten.
    public override void Encrypt(Stream stream)
    {
        if (stream == null)
            throw new ArgumentNullException(nameof(stream));
        Current.ComputeHash(stream, out var num);
        HashNumber = num;
        RawHash = CryptoUtils.GetByteArray(num, RawHashSize, true);
    }
}
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

