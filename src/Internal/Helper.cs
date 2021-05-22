namespace Roydl.Crypto.Internal
{
    using System;
    using System.Collections;
    using System.IO;

    internal static class Helper
    {
        internal static void DestroyElement<TElement>(ref TElement element) where TElement : class
        {
            if (element == null)
                return;
            var isCollection = false;
            switch (element)
            {
                case ICollection:
                    isCollection = element is not Array;
                    break;
                case IDisposable disposable:
                    disposable.Dispose();
                    break;
            }
            var generation = GC.GetGeneration(element);
            element = null;
            GC.Collect(generation, GCCollectionMode.Forced);
            if (isCollection)
                GC.Collect();
        }

        internal static int GetBufferSize(Stream stream)
        {
            const int kb128 = 0x20000;
            const int kb64 = 0x10000;
            const int kb32 = 0x8000;
            const int kb16 = 0x4000;
            const int kb8 = 0x2000;
            const int kb4 = 0x1000;
            return (int)Math.Floor((stream?.Length ?? 0) / 1.5d) switch
            {
                > kb128 => kb128,
                > kb64 => kb64,
                > kb32 => kb32,
                > kb16 => kb16,
                > kb8 => kb8,
                _ => kb4
            };
        }
    }
}
