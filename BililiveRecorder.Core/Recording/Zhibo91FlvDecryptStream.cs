using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace BililiveRecorder.Core.Recording
{
    /// <summary>
    /// 实时解密 91Zhibo 的 FLV 视频 Tag。
    /// </summary>
    internal sealed class Zhibo91FlvDecryptStream : Stream
    {
        private const int FlvHeaderSize = 13;
        private const int TagHeaderSize = 11;
        private const int PreviousTagSizeLength = 4;

        private readonly Stream innerStream;

        private FlvSection section = FlvSection.FileHeader;
        private int sectionOffset;
        private int tagDataSize;
        private int payloadOffset;
        private byte tagType;
        private byte previousDecryptedByte;
        private bool decryptCurrentTag;
        private long bytesProcessed;

        public Zhibo91FlvDecryptStream(Stream innerStream)
        {
            this.innerStream = innerStream ?? throw new ArgumentNullException(nameof(innerStream));
        }

        public long DecryptedTagCount { get; private set; }

        /// <summary>
        /// 最后一个完整 FLV Tag 的结束位置。直播流在 Tag 中途断开时，可用此位置安全截断文件。
        /// </summary>
        public long LastCompleteTagEndPosition { get; private set; }

        public override bool CanRead => this.innerStream.CanRead;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() => this.innerStream.Flush();

        public override int Read(byte[] buffer, int offset, int count)
        {
            var bytesRead = this.innerStream.Read(buffer, offset, count);
            this.Transform(buffer, offset, bytesRead);
            return bytesRead;
        }

        public override int ReadByte()
        {
            var value = this.innerStream.ReadByte();
            return value < 0 ? value : this.TransformByte((byte)value);
        }

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            var bytesRead = await this.innerStream.ReadAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false);
            this.Transform(buffer, offset, bytesRead);
            return bytesRead;
        }

#if NET6_0_OR_GREATER
        public override int Read(Span<byte> buffer)
        {
            var bytesRead = this.innerStream.Read(buffer);
            this.Transform(buffer[..bytesRead]);
            return bytesRead;
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var bytesRead = await this.innerStream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            this.Transform(buffer, bytesRead);
            return bytesRead;
        }

        public override async ValueTask DisposeAsync()
        {
            await this.innerStream.DisposeAsync().ConfigureAwait(false);
            GC.SuppressFinalize(this);
        }
#endif

        protected override void Dispose(bool disposing)
        {
            if (disposing)
                this.innerStream.Dispose();

            base.Dispose(disposing);
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        private void Transform(byte[] buffer, int offset, int count)
        {
            var end = offset + count;
            for (var i = offset; i < end; i++)
                buffer[i] = this.TransformByte(buffer[i]);
        }

#if NET6_0_OR_GREATER
        private void Transform(Span<byte> buffer)
        {
            for (var i = 0; i < buffer.Length; i++)
                buffer[i] = this.TransformByte(buffer[i]);
        }

        private void Transform(Memory<byte> buffer, int count) => this.Transform(buffer.Span[..count]);
#endif

        private byte TransformByte(byte value)
        {
            this.bytesProcessed++;

            switch (this.section)
            {
                case FlvSection.FileHeader:
                    this.sectionOffset++;
                    if (this.sectionOffset == FlvHeaderSize)
                    {
                        this.LastCompleteTagEndPosition = this.bytesProcessed;
                        this.MoveToTagHeader();
                    }
                    return value;

                case FlvSection.TagHeader:
                    this.ReadTagHeaderByte(value);
                    return value;

                case FlvSection.Payload:
                    value = this.DecryptPayloadByte(value);
                    this.payloadOffset++;
                    if (this.payloadOffset == this.tagDataSize)
                        this.MoveToPreviousTagSize();
                    return value;

                case FlvSection.PreviousTagSize:
                    this.sectionOffset++;
                    if (this.sectionOffset == PreviousTagSizeLength)
                    {
                        this.LastCompleteTagEndPosition = this.bytesProcessed;
                        this.MoveToTagHeader();
                    }
                    return value;

                default:
                    throw new InvalidOperationException("Unknown FLV parser state.");
            }
        }

        private void ReadTagHeaderByte(byte value)
        {
            switch (this.sectionOffset)
            {
                case 0:
                    this.tagType = value;
                    this.tagDataSize = 0;
                    break;
                case 1:
                case 2:
                case 3:
                    this.tagDataSize = (this.tagDataSize << 8) | value;
                    break;
            }

            this.sectionOffset++;
            if (this.sectionOffset != TagHeaderSize)
                return;

            if (this.tagDataSize == 0)
                this.MoveToPreviousTagSize();
            else
                this.MoveToPayload();
        }

        private byte DecryptPayloadByte(byte value)
        {
            if (this.payloadOffset == 0)
            {
                this.decryptCurrentTag = this.tagType == 9 && (value & 0x0F) == 13;
                if (this.decryptCurrentTag)
                {
                    this.DecryptedTagCount++;
                    return (byte)((value & 0xF0) | 12);
                }

                return value;
            }

            if (!this.decryptCurrentTag)
                return value;

            if (this.payloadOffset == 1)
            {
                this.previousDecryptedByte = value;
                return value;
            }

            this.previousDecryptedByte ^= value;
            return this.previousDecryptedByte;
        }

        private void MoveToTagHeader()
        {
            this.section = FlvSection.TagHeader;
            this.sectionOffset = 0;
            this.tagDataSize = 0;
            this.payloadOffset = 0;
            this.decryptCurrentTag = false;
        }

        private void MoveToPayload()
        {
            this.section = FlvSection.Payload;
            this.payloadOffset = 0;
            this.decryptCurrentTag = false;
        }

        private void MoveToPreviousTagSize()
        {
            this.section = FlvSection.PreviousTagSize;
            this.sectionOffset = 0;
        }

        private enum FlvSection
        {
            FileHeader,
            TagHeader,
            Payload,
            PreviousTagSize,
        }
    }
}
