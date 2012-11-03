//Public Domain
using System;
using System.IO;
using KeyczarTool.Minified.Diminish.SevenZip.Compression.LZMA;

namespace KeyczarTool.Minified.Diminish.SevenZip
{
    public static class Zipper
    {
	    public static void Encode(Stream input, Stream output)
        {
            var coder = new Encoder();
            var propIDs = new[]
                               {
                                   CoderPropID.DictionarySize, 
                                   CoderPropID.PosStateBits, 
                                   CoderPropID.LitContextBits, 
                                   CoderPropID.LitPosBits,
                                   CoderPropID.Algorithm, 
                                   CoderPropID.NumFastBytes,
                                   CoderPropID.MatchFinder,
                                   CoderPropID.EndMarker
                               };
            var properties = new object[]
                                  {
                                      0x800000,
                                      2,
                                      3,
                                      0,
                                      2,
                                      0x8,
                                      "bt4",
                                      false
                                  };

            coder.SetCoderProperties(propIDs, properties);
            coder.WriteCoderProperties(output);
            var fileSize = input.Length;

	        var byterep =BitConverter.GetBytes(fileSize);
            if(!BitConverter.IsLittleEndian)
                Array.Reverse(byterep);
            output.Write(byterep,0, byterep.Length);
            coder.Code(input, output, -1L, -1L, null);

        }

         public static void Decode(Stream input, Stream output)
        {
                var coder = new Decoder();
                var outSize = 0L;
                var compressedSize = input.Length - input.Position;
                var properties = new byte[5];
                input.Read(properties, 0, 5);
                coder.SetDecoderProperties(properties);
                var bytesize = new byte[8];
                input.Read(bytesize, 0, 8);
                if(!BitConverter.IsLittleEndian)
                    Array.Reverse(bytesize);
                outSize = BitConverter.ToInt64(bytesize, 0);
                coder.Code(input, output, compressedSize, outSize, null);
        }
	}
}