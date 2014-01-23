﻿using System;
using System.Collections.Generic;
using Chaos.NaCl.Internal;

namespace Chaos.NaCl
{
    public class Sha512
    {
        private Array8<UInt64> _state;
        private readonly byte[] _buffer;
        private ulong _totalBytes;
        public const int BlockSize = 128;
        private static readonly byte[] _padding = new byte[] { 0x80 };

        public Sha512()
        {
            _buffer = new byte[BlockSize];//todo: remove allocation
            Init();
        }

        public void Init()
        {
            Sha512Internal.Sha512Init(out _state);
            _totalBytes = 0;
        }

        public void Update(byte[] data, int offset, int count)
        {
            Array16<ulong> block;
            int bytesInBuffer = (int)_totalBytes & (BlockSize - 1);
            _totalBytes += (uint)count;

            if (_totalBytes >= ulong.MaxValue / 8)
                throw new InvalidOperationException("Too much data");
            // Fill existing buffer
            if (bytesInBuffer != 0)
            {
                var toCopy = Math.Min(BlockSize - bytesInBuffer, count);
                Buffer.BlockCopy(data, offset, _buffer, bytesInBuffer, toCopy);
                offset += toCopy;
                count -= toCopy;
                bytesInBuffer += toCopy;
                if (bytesInBuffer == BlockSize)
                {
                    ByteIntegerConverter.Array16LoadBigEndian64(out block, _buffer, 0);
                    Sha512Internal.Core(out _state, ref _state, ref block);
                    CryptoBytes.InternalWipe(_buffer, 0, _buffer.Length);
                    bytesInBuffer = 0;
                }
            }
            // Hash complete blocks without copying
            while (count >= BlockSize)
            {
                ByteIntegerConverter.Array16LoadBigEndian64(out block, data, offset);
                Sha512Internal.Core(out _state, ref _state, ref block);
                offset += BlockSize;
                count -= BlockSize;
            }
            // Copy remainder into buffer
            if (count > 0)
            {
                Buffer.BlockCopy(data, offset, _buffer, bytesInBuffer, count);
            }
        }

        public byte[] Finish()
        {
            Update(_padding, 0, _padding.Length);
            Array16<ulong> block;
            ByteIntegerConverter.Array16LoadBigEndian64(out block, _buffer, 0);
            CryptoBytes.InternalWipe(_buffer, 0, _buffer.Length);
            int bytesInBuffer = (int)_totalBytes & (BlockSize - 1);
            if (bytesInBuffer > BlockSize - 16)
            {
                Sha512Internal.Core(out _state, ref _state, ref block);
                block = default(Array16<ulong>);
            }
            block.x15 = (_totalBytes - 1) * 8;
            Sha512Internal.Core(out _state, ref _state, ref block);

            var result = new byte[64];
            ByteIntegerConverter.StoreBigEndian64(result, 0, _state.x0);
            ByteIntegerConverter.StoreBigEndian64(result, 8, _state.x1);
            ByteIntegerConverter.StoreBigEndian64(result, 16, _state.x2);
            ByteIntegerConverter.StoreBigEndian64(result, 24, _state.x3);
            ByteIntegerConverter.StoreBigEndian64(result, 32, _state.x4);
            ByteIntegerConverter.StoreBigEndian64(result, 40, _state.x5);
            ByteIntegerConverter.StoreBigEndian64(result, 48, _state.x6);
            ByteIntegerConverter.StoreBigEndian64(result, 56, _state.x7);
            _state = default(Array8<ulong>);
            return result;
        }

        public static byte[] Hash(byte[] data)
        {
            return Hash(data, 0, data.Length);
        }

        public static byte[] Hash(byte[] data, int offset, int count)
        {
            var hasher = new Sha512();
            hasher.Update(data, offset, count);
            return hasher.Finish();
        }
    }
}
