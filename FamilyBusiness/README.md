# TeamItaly CTF 2022

## Family business (1 solve)

You're given a bunch of unknown binary ".pizza" files and a README.md showing how these file are used to encapsulate media. The objective of the challenge is to write a demuxer, convert the videos in a playable format and find all flag pieces present in each file.

### Solution (intended)

The intended solution for this challenge is to integrate a decoder for the PIZF format in `libavformat`, which is part of ffmpeg.

This way we'll be able to decode the format by using a simple ffmpeg format, but we'll have to write a few lines of C.

After cloning the ffmpeg repo, we can start by creating a `pizfdec.h` file in the `libavformat` folder, which will contain our decoder.

Reference `pizfdec.h`

```C
#include "libavutil/pixdesc.h"
#include "libavutil/intreadwrite.h"
#include "avformat.h"
#include "internal.h"

// Constants (could also go in a separate file)
#define PIZF_MAGIC      MKTAG('P', 'I', 'Z', 'F')

#define PIZF_TXT        MKTAG('_', 'T', 'X', 'T')
#define PIZF_AUD        MKTAG('_', 'A', 'U', 'D')
#define PIZF_VID        MKTAG('_', 'V', 'I', 'D')
#define PIZF_END        MKTAG('_', 'E', 'N', 'D')

#define PIZF_DATA_AUD   MKTAG('d', 'A', 'U', 'D')
#define PIZF_DATA_VID   MKTAG('d', 'V', 'I', 'D')
#define PIZF_DATA_END   MKTAG('d', 'E', 'N', 'D')

const AVCodecTag ff_codec_pizf_video_tags[] = {
    { AV_CODEC_ID_MJPEG,    MKTAG('v', 'J', 'P', 'G') },
    { AV_CODEC_ID_H265,     MKTAG('v', 'H', '6', '5') },
    { AV_CODEC_ID_H264,     MKTAG('v', 'H', '6', '4') },
    { AV_CODEC_ID_MPEG4,    MKTAG('v', 'M', 'P', '4') },
    { AV_CODEC_ID_WMV2,     MKTAG('v', 'W', 'M', 'V') },
    { AV_CODEC_ID_VP9,      MKTAG('v', 'V', 'P', '9') },
    { AV_CODEC_ID_AV1,      MKTAG('v', 'A', 'V', '1') },
    { AV_CODEC_ID_NONE,     0 },
};

const AVCodecTag ff_codec_pizf_audio_tags[] = {
    { AV_CODEC_ID_AAC,    MKTAG('a', 'A', 'A', 'C') },
    { AV_CODEC_ID_MP3,    MKTAG('a', 'M', 'P', '3') },
    { AV_CODEC_ID_VORBIS, MKTAG('a', 'V', 'B', 'S')},
    { AV_CODEC_ID_FLAC,   MKTAG('a', 'F', 'L', 'C')},
    { AV_CODEC_ID_OPUS,   MKTAG('a', 'O', 'P', 'S')},
    { AV_CODEC_ID_NONE,   0 },
};


// Determine if a file is a PIZF file
static int pizf_probe(const AVProbeData* p) {
    if (AV_RL32(&p->buf[0]) == PIZF_MAGIC)
        return AVPROBE_SCORE_MAX;
    return 0;
}

// Read PIZF file header
static int pizf_read_header(AVFormatContext *c) {
    AVIOContext *pb = c->pb;

    uint8_t stream_count;
    uint16_t version;
    uint32_t duration;

    AVStream* streams[255];

    avio_skip(pb, 4); // Skip magic
    version = avio_rb16(pb); // Read version
    // Check version
    if (version != 31) {
        av_log(c, AV_LOG_ERROR, "Unknown version\n");
        return AVERROR_INVALIDDATA;
    }
    stream_count = avio_r8(pb);
    duration = avio_rb32(pb); // Read duration

    // Loop until end of file
    while (!avio_feof(pb)) {
        uint32_t tag_type, tag_size;
        uint64_t start;

        tag_type = avio_rl32(pb); // Read tag type (LE)
        tag_size = avio_rb32(pb); // Read tag size

        start = avio_tell(pb); // Save position

        switch (tag_type) {
        case PIZF_AUD: {
            uint8_t stream_id;
            uint64_t extradata_size;

            stream_id = avio_r8(pb);

            // Initialize stream
            streams[stream_id] = avformat_new_stream(c, 0);
            streams[stream_id]->codecpar->codec_type  = AVMEDIA_TYPE_AUDIO;

            // Read values
            streams[stream_id]->codecpar->sample_rate = avio_rb16(pb);
            streams[stream_id]->codecpar->bits_per_coded_sample = avio_r8(pb);
            streams[stream_id]->codecpar->ch_layout.nb_channels = avio_r8(pb);
            streams[stream_id]->codecpar->codec_tag = avio_rl32(pb);
            streams[stream_id]->duration = duration;

            // Find codec id
            streams[stream_id]->codecpar->codec_id =
                    ff_codec_get_id(ff_codec_pizf_audio_tags,
                                    streams[stream_id]->codecpar->codec_tag);

            // Find extradata size
            extradata_size = tag_size - (avio_tell(pb) - start);
            if (extradata_size > 0) {
                // Initialize extradata
                streams[stream_id]->codecpar->extradata =
                    av_malloc(extradata_size + AV_INPUT_BUFFER_PADDING_SIZE);
                streams[stream_id]->codecpar->extradata_size = extradata_size;

                // Read extradata
                avio_read(pb, streams[stream_id]->codecpar->extradata, extradata_size);
            }

            // PTS is always 32 bit, 1/1000
            avpriv_set_pts_info(streams[stream_id], 32, 1, 1000);

            break;
        }
        case PIZF_VID: {
            uint8_t stream_id;
            uint64_t extradata_size;
            char format_name[16] = {0};

            stream_id = avio_r8(pb);

            // Init stream
            streams[stream_id] = avformat_new_stream(c, 0);
            streams[stream_id]->codecpar->codec_type = AVMEDIA_TYPE_VIDEO;

            // Populate values
            streams[stream_id]->codecpar->width = avio_rb32(pb);
            streams[stream_id]->codecpar->height = avio_rb32(pb);
            avio_read(pb, format_name, 16);
            streams[stream_id]->codecpar->codec_tag = avio_rl32(pb);
            streams[stream_id]->duration = duration;

            // Find and set pixel format
            streams[stream_id]->codecpar->format = av_get_pix_fmt(format_name);

            // Find codec id
            streams[stream_id]->codecpar->codec_id =
                    ff_codec_get_id(ff_codec_pizf_video_tags,
                                    streams[stream_id]->codecpar->codec_tag);

            // Find extradata size
            extradata_size = tag_size - (avio_tell(pb) - start);
            if (extradata_size > 0) {
                // Initialize extradata
                streams[stream_id]->codecpar->extradata =
                    av_malloc(extradata_size + AV_INPUT_BUFFER_PADDING_SIZE);
                streams[stream_id]->codecpar->extradata_size = extradata_size;

                // Copy extradata
                avio_read(pb, streams[stream_id]->codecpar->extradata, extradata_size);
            }

            // PTS is always 32 bit, 1/1000
            avpriv_set_pts_info(streams[stream_id], 32, 1, 1000);
            break;
        }
        case PIZF_TXT: {
            uint32_t key_size, value_size;
            char *key, *value;

            // Find sizes
            key_size = avio_rb32(pb);
            value_size = tag_size - key_size - 4;

            // Allocate space
            key = av_malloc(key_size + 1);
            value = av_malloc(value_size + 1);

            // Read values
            avio_read(pb, key, key_size);
            avio_read(pb, value, value_size);

            // Add terminator
            key[key_size] = 0;
            value[value_size] = 0;

            // Write to metadata dict
            av_dict_set(&c->metadata,
                        key,
                        value,
                        AV_DICT_DONT_STRDUP_KEY | AV_DICT_DONT_STRDUP_VAL);

            break;
        }
        case PIZF_END:
            return 0;
        default:
            av_log(c, AV_LOG_ERROR, "Unknown header tag\n");
            return AVERROR_INVALIDDATA;
        }

    }

    return AVERROR_EOF;

}

// Read PIZF packet
static int pizf_read_packet(AVFormatContext *c, AVPacket *pkt) {
    AVIOContext *pb = c->pb;
    int ret;
    uint32_t tag_type, pos;

    pos = avio_tell(pb); // Save packet position
    tag_type = avio_rl32(pb); // Get tag type

    switch (tag_type) {
        case PIZF_DATA_AUD:
        case PIZF_DATA_VID: {
            uint8_t stream_id;
            uint32_t pts, size;

            // Save values
            stream_id = avio_r8(pb);
            pts = avio_rb32(pb);
            size = avio_rb32(pb);

            // Initialize packet
            ret = av_get_packet(pb, pkt, size);

            // Write packet values
            pkt->stream_index = stream_id;
            pkt->pts = pts;
            pkt->pos = pos; // Required
            break;
        }
        case PIZF_DATA_END: {
            ret = AVERROR_EOF;
            pb->eof_reached = 1; // Force stream end
            break;
        }
        default: {
            av_log(c, AV_LOG_ERROR, "Unknown data tag\n");
            ret = AVERROR_INVALIDDATA;
        }
    }

    return ret;
}

// Define demuxer properties
const AVInputFormat ff_pizf_demuxer = {
    .name           =   "pizf",
    .long_name      =   NULL_IF_CONFIG_SMALL("Pizza File"),
    .extensions      =  "pizf,pizza",
    .read_probe     =   pizf_probe,
    .read_header    =   pizf_read_header,
    .read_packet    =   pizf_read_packet,
};
```

Now we have to register the codec:

In `libavformat` > `allformats.c`, we have to add

```C=27
extern const AVInputFormat ff_pizf_demuxer;
```

While in `libavformat` > `Makefile`

```Make=73
OBJS-$(CONFIG_PIZF_DEMUXER)              += pizfdec.o
```

Before building, we have to run the configure script. We'll also enable some libraries in order to decode all codecs

```bash
./configure --enable-libdav1d --enable-libx264
```

We have to install `libdav1d-dev` and `libx264-dev` if we don't have it already, as they're required to decode the `av1` codec and re-encode everything in `h264`.

Make sure the `pizf` demuxer is enabled and, finally, build and install your ffmpeg version with

```bash
make -j10
sudo make install
```

Now, we can convert the files back to a playable format by issuing

```
ffmpeg -i Pizza/Welcome.pizza Welcome.mp4
```

There are a total of 7 flag pieces in this challenge.
Most of them are directy shown in the video but some are more hidden (\*).

|    Video     | Flag piece                  | Vcodec |  Acodec   |   #   |
| :----------: | :-------------------------- | :----: | :-------: | :---: |
|   Welcome    | `flag{cu570m_...}`          |  h264  |    mp3    | (1/7) |
|   History    | `flag{...f0rm4t5_...}`      | mjpeg  |  libopus  | (2/7) |
|  Margherita  | `flag{...4r3_n1c3_...}`     |  hevc  |   flac    | (3/7) |
|    Flag\*    | `flag{...4nd_4ll_bu7_...}`  | mpeg4  |    aac    | (4/7) |
|  Traditions  | `flag{...7h3_53cr37_...}`   |  wmv   | libvorbis | (5/7) |
| Technology\* | `flag{...1ngr3d13n7_15...}` |  vp9   |    aac    | (6/7) |
|   Variety    | `flag{..._l0v3!_76369}`     |  av1   |  libopus  | (7/7) |

Piece #4 is encoded as hex and written as a comment in the file metadata.
Piece #6 is spelled out during the audio playback of the file.

After successfully finding all the pieces you can rebuild the complete flag

`flag{cu570m_f0rm4t5_4r3_n1c3_4nd_4ll_bu7_7h3_53cr37_1ngr3d13n7_15_l0v3!_76369}`

### Solution (semi-intended)

What if I hate C and want to write a demuxer in python?

Writing a demuxer to separate the streams is very easy, the real challenge lies in how to properly decode/remux them.

Since there are many different codecs, I expect someone using this solution to manually handle all the different quirks each of them has.

I still think it's possible, just harder. Especially since it seems wmv has no way of knowing the end of packets (and it's just weird and microsofty)

Python FFmpeg library bindings seem promising, but are a pain to use (and also seem unable to get you all the way)
