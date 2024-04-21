// Copyright 2021, 2024 Dolphin Emulator Project, theKidOfArcrania
// SPDX-License-Identifier: GPL-2.0-or-later

#include "DolphinTool/PatchCommand.h"
#include "DolphinTool/SectionStream.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <vector>
#include <filesystem>
#include <unordered_map>

#include <mbedtls/sha256.h>
#include <mbedtls/error.h>

#include <OptionParser.h>
#include <fmt/format.h>
#include <fmt/ostream.h>

#include "Common/CommonTypes.h"
#include "Common/Hash.h"
#include "DiscIO/Blob.h"
#include "DiscIO/DiscExtractor.h"
#include "DiscIO/DiscUtils.h"
#include "DiscIO/ScrubbedBlob.h"
#include "DiscIO/Volume.h"
#include "DiscIO/VolumeDisc.h"
#include "DiscIO/WIABlob.h"

#include "xdelta3.h"
#include "xdelta3-internal.h"

namespace fs = std::filesystem;

namespace DolphinTool
{

typedef std::function<bool(const std::string& path)> UpdateCB;

static std::optional<DiscIO::WIARVZCompressionType>
ParseCompressionTypeString(const std::string& compression_str)
{
  if (compression_str == "none")
    return DiscIO::WIARVZCompressionType::None;
  else if (compression_str == "purge")
    return DiscIO::WIARVZCompressionType::Purge;
  else if (compression_str == "bzip2")
    return DiscIO::WIARVZCompressionType::Bzip2;
  else if (compression_str == "lzma")
    return DiscIO::WIARVZCompressionType::LZMA;
  else if (compression_str == "lzma2")
    return DiscIO::WIARVZCompressionType::LZMA2;
  else if (compression_str == "zstd")
    return DiscIO::WIARVZCompressionType::Zstd;
  return std::nullopt;
}

static std::optional<DiscIO::BlobType> ParseFormatString(const std::string& format_str)
{
  if (format_str == "iso")
    return DiscIO::BlobType::PLAIN;
  else if (format_str == "gcz")
    return DiscIO::BlobType::GCZ;
  else if (format_str == "wia")
    return DiscIO::BlobType::WIA;
  else if (format_str == "rvz")
    return DiscIO::BlobType::RVZ;
  return std::nullopt;
}

static uint32_t CountFiles(
    const DiscIO::Volume &volume,
    const DiscIO::Partition &partition)
{
  auto fs = volume.GetFileSystem(partition);
  if (!fs) {
    return 0;
  }

  uint32_t count = 0;
  std::vector<std::unique_ptr<DiscIO::FileInfo>> queue;
  queue.push_back(fs->GetRoot().clone());
  while (!queue.empty()) {
    auto dir = queue.back()->clone();
    queue.pop_back();
    count += 1;
    if (dir->IsDirectory()) {
      for (auto &file: *dir) {
        queue.push_back(file.clone());
      }
    }
  }
  return count;
}

static bool ExtractPartition(
    const DiscIO::Volume &volume,
    const DiscIO::Partition &partition,
    const std::string &export_path,
    const UpdateCB& update_progress)
{
  // Extract files
  auto files_out = export_path + "/files";
  if (!fs::create_directory(files_out)) {
    fmt::println(std::cerr, "mpatch: Unable to create directory: {}", files_out);
    return false;
  }

  auto fs = volume.GetFileSystem(partition);
  if (!fs) {
    return true;
  }

  DiscIO::ExportDirectory(volume, partition, fs->GetRoot(), true, "", files_out, update_progress);

  // Extract system data
  if (!DiscIO::ExportSystemData(volume, partition, export_path)) {
    fmt::println(std::cerr, "Error: Unable to export system data");
    return false;
  }
  return true;
}

static const char ALPHANUM[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
class TempDirectory {
public:
  static TempDirectory Create() {
    if (!fs::is_directory(fs::temp_directory_path())) {
      fmt::println(std::cerr, "Error: unable to create temp directory");
      abort();
    }
    for(;;) {
      std::string name{ "tmpdir" };
      for (int i = 0; i < 12; i++) {
        name += ALPHANUM[generator() % (sizeof(ALPHANUM) - 1)];
      }
      auto path = fs::temp_directory_path() / name;
      if (fs::create_directory(path)) {
        return TempDirectory(path);
      }
    }
  }

  ~TempDirectory() {
    if (this->m_path) {
      fs::remove_all(*this->m_path);
    }
  }

  TempDirectory() = delete;
  TempDirectory(const TempDirectory& val) = delete;
  TempDirectory(TempDirectory&& val): m_path(std::move(val.m_path)) {
    val.m_path = std::nullopt;
  };

  TempDirectory& operator=(const TempDirectory& other) = delete;

  TempDirectory& operator=(TempDirectory&& other) {
    if (this->m_path) {
      fs::remove_all(*this->m_path);
    }
    this->m_path = other.m_path;
    other.m_path = std::nullopt;
    return *this;
  }

  const std::string& path() const {
    return *this->m_path;
  }

private:
  std::optional<std::string> m_path;

  explicit TempDirectory(std::string path): m_path(std::move(path)) {}

  static std::random_device rd;
  static std::default_random_engine generator;
};

std::random_device TempDirectory::rd;
std::default_random_engine TempDirectory::generator{ TempDirectory::rd() };

#define XD3_LIB_ERRMSG(stream, ret) "{}: {}", \
    xd3_errstring (stream), xd3_mainerror (ret)

#define OTRY(x) ({ \
  auto __x = (x); \
  if (!__x) return std::nullopt; \
  std::move(*__x); \
})

class delayed_source {
public:
  typedef std::optional<std::pair<FILE*, std::unique_ptr<std::ostream>>> initializer_return;
  typedef std::optional<std::function<initializer_return(const uint8_t *, usize_t)>> initializer_type;
  delayed_source(FILE *source, std::unique_ptr<std::ostream> out):
    m_initer(std::nullopt), m_source(source), m_out(std::move(out))
  {
  }

  delayed_source(const initializer_type &initer): m_initer(std::optional(initer)),
    m_source(nullptr), m_out(nullptr)
  {
  }

  ~delayed_source() {
    if (m_source && *m_source) {
      fclose(*m_source);
    }

    if (m_out) {
      m_out->flush();
    }
  }

  FILE *try_source() {
    if (!this->m_source) {
      return nullptr;
    } else {
      return *this->m_source;
    }
  }

  FILE *source() {
    return *this->m_source;
  }

  std::ostream& out() {
    return *this->m_out;
  }

  bool got_header(const uint8_t *appdata, usize_t size, bool &inited) {
    inited = !this->m_initer.has_value();
    if (this->m_initer) {
      auto ret = (*this->m_initer)(appdata, size);
      if (!ret) {
        return false;
      }
      this->m_initer = std::nullopt;
      this->m_source = (*ret).first;
      this->m_out = std::move((*ret).second);
    }

    return true;
  }
private:
  initializer_type m_initer;
  std::optional<FILE *> m_source;
  std::unique_ptr<std::ostream> m_out;
};

static bool set_source(FILE *src_file, xd3_stream &stream, xd3_source &src) {
  if (fseek(src_file, 0, SEEK_END) < 0) {
    return false;
  }
  auto size = ftell(src_file);
  if (size < 0) {
    return false;
  }
  if (fseek(src_file, 0, SEEK_SET) < 0) {
    return false;
  }

  src.curblkno = 0;
  src.onblk = fread((void*)src.curblk, 1, src.blksize, src_file);

  xd3_set_source_and_size(&stream, &src, size);
  return true;
}

static bool XD3Entry(bool encode, std::istream &in, delayed_source &delay,
    const std::function<void (xd3_stream&)> &configure) {
  int ret;
  uint8_t *input_buf;
  std::streamsize read;
  xd3_stream stream{};
  xd3_config config{};
  xd3_source src{};
  bool flushed = false;

  xd3_init_config(&config, XD3_ADLER32);
  config.winsize = XD3_ALLOCSIZE;
  if ((ret = xd3_config_stream(&stream, &config))) {
    fmt::println(std::cerr, "xdelta3: xd3_config_stream: " XD3_LIB_ERRMSG(&stream, ret));
  }

  src.blksize = XD3_ALLOCSIZE;
  src.curblk = new uint8_t[src.blksize];

  auto maybe_src = delay.try_source();
  if (maybe_src) {
    if (!set_source(maybe_src, stream, src)) {
      fmt::println(std::cerr, "mpatch: Unable to load source file");
      return false;
    }
  }

  configure(stream);

  input_buf = new uint8_t[XD3_ALLOCSIZE];
  while ((read = in.read((char*)input_buf, XD3_ALLOCSIZE).gcount()) != 0 || !flushed) {
    if (read < XD3_ALLOCSIZE) {
      xd3_set_flags(&stream, XD3_FLUSH | stream.flags);
      flushed = true;
    } else {
      flushed = false;
    }
    xd3_avail_input(&stream, input_buf, read);

    // Encode to patch
  process:
    if (encode) {
      ret = xd3_encode_input(&stream);
    } else {
      ret = xd3_decode_input(&stream);
    }
    switch (ret) {
      case XD3_INPUT:
        continue;
      case XD3_OUTPUT:
        if (!delay.out().write((char*)stream.next_out, stream.avail_out)) {
          fmt::println(std::cerr, "mpatch: failed to write to output file");
          return false;
        }

        xd3_consume_output(&stream);
        goto process;
      case XD3_GOTHEADER:
        {
          uint8_t *appdata;
          usize_t size;
          if ((ret = xd3_get_appheader(&stream, &appdata, &size))) {
            fmt::println(std::cerr, "xdelta3: xd3_get_appheader: " XD3_LIB_ERRMSG(&stream, ret));
            return false;
          }

          bool inited;
          if (!delay.got_header(appdata, size, inited)) {
            return false;
          }

          if (!inited) {
            auto maybe_src2 = delay.source();
            if (maybe_src2) {
              if (!set_source(maybe_src2, stream, src)) {
                fmt::println(std::cerr, "mpatch: Unable to load source file");
                return false;
              }
            }
          }
        }
        // FALLTHROUGH
      case XD3_WINSTART:
      case XD3_WINFINISH:
        goto process;
      case XD3_GETSRCBLK:
        {
          auto src_file = delay.source();
          if (delay.source()) {
            if (fseek(src_file, src.blksize * src.getblkno, SEEK_SET)) {
              fmt::println(std::cerr, "mpatch: Unable to seek in file");
              return false;
            }
            src.onblk = fread((void*)src.curblk, 1, src.blksize, src_file);
          }
          src.curblkno = src.getblkno;
          goto process;
        }
      case XD3_INVALID_INPUT:
        fmt::println(std::cerr, "xdelta3: " XD3_LIB_ERRMSG(&stream, ret));
        return false;
      default:
        fmt::println(std::cerr, "xdelta3: INVALID STATE: {}", ret);
        fmt::println(std::cerr, "xdelta3: " XD3_LIB_ERRMSG(&stream, ret));
        return false;
    }
  }

  delete[] src.curblk;
  delete[] input_buf;

  if ((ret = xd3_close_stream(&stream))) {
    fmt::println(std::cerr, "xdelta3: xd3_close_stream: " XD3_LIB_ERRMSG(&stream, ret));
    return false;
  }

  xd3_free_stream(&stream);

  return true;
}

static std::optional<std::string> FileHash(const std::string &file) {
  std::ifstream reader;
  mbedtls_sha256_context ctx;
  char *buff = new char[0x1000];
  std::optional<std::string> retval = std::nullopt;
  int ret;
  std::streamsize read;

  reader.open(file);
  if (!reader) {
    fmt::println(std::cerr, "mpatch: Unable to open input file: {}", file.c_str());
    goto cleanup;
  }


  mbedtls_sha256_init(&ctx);

  while ((read = reader.read(buff, 0x1000).gcount()) > 0) {
    if (reader.bad()) {
      fmt::println(std::cerr, "mpatch: Unable to read input file: {}", file.c_str());
      goto cleanup2;
    }

    if ((ret = mbedtls_sha256_update_ret(&ctx, (u8*)buff, read)) < 0) {
      fmt::println(std::cerr, "mpatch: {}: Hash computation failed ({}): {}",
          file.c_str(), ret, mbedtls_high_level_strerr(ret));
      goto cleanup2;
    }
  }

  u8 out_buf[32];
  if ((ret = mbedtls_sha256_finish_ret(&ctx, out_buf)) < 0) {
    fmt::println(std::cerr, "mpatch: {}: Final hash computation failed ({}): {}",
        file.c_str(), ret, mbedtls_high_level_strerr(ret));
    goto cleanup2;
  }

  retval = std::string((char*)out_buf, sizeof(out_buf));

cleanup2:
  mbedtls_sha256_free(&ctx);
cleanup:
  delete[] buff;
  return retval;
}

static bool WritePatch(
    std::ostream &patch,
    const TempDirectory &source_dir,
    const TempDirectory &compare_dir,
    const std::string &file,
    const std::unordered_map<std::string, std::string> &src_file_hashes) {

  FILE *src_file = nullptr;
  std::ifstream in_file;

  auto compare_path = compare_dir.path() + "/" + file;
  in_file.open(compare_path.c_str());
  if (!in_file) {
    fmt::println(std::cerr, "mpatch: Unable to open input file: {}",
        compare_path.c_str());
    return false;
  }

  auto compare_hash = ({
    auto tmp = FileHash(compare_path);
    if (!tmp) {
      return false;
    }
    *tmp;
  });

  auto src_file_path = file;
  if (src_file_hashes.contains(compare_hash)) {
    src_file_path = src_file_hashes.at(compare_hash);

    auto source_path = source_dir.path() + "/" + file;
    src_file = fopen(source_path.c_str(), "r");
    if (src_file == nullptr) {
      fmt::println(std::cerr, "mpatch: Unable to open source file: {}", source_path.c_str());
      return false;
    }
  } else {
    src_file = fopen((source_dir.path() + "/" + file).c_str(), "r");
  }

  wrbuf_section patch_buf(patch);
  delayed_source source(src_file, std::make_unique<std::ostream>(&patch_buf));
  auto ret = XD3Entry(true, in_file, source, [&file, &src_file_path](xd3_stream &config) {
    uint32_t src_file_off = sizeof(Xdelta3PatchHeader);
    uint32_t out_file_off = src_file_off + src_file_path.length() + 1;
    usize_t header_len = sizeof(Xdelta3PatchHeader) + 2 + file.length() + src_file_path.length();
    uint8_t *header = new uint8_t[header_len];
    *reinterpret_cast<Xdelta3PatchHeader*>(header) = Xdelta3PatchHeader {
      PATCH_MAGIC,
      src_file_off,
      out_file_off,
    };
    memcpy(header + src_file_off, src_file_path.c_str(), src_file_path.length());
    header[out_file_off - 1] = 0;
    memcpy(header + out_file_off, file.c_str(), file.length());
    header[out_file_off + file.length()] = 0;
    xd3_set_appheader(&config, header, header_len);
  });
  if (patch_buf.pubsync() < 0) {
    fmt::println(std::cerr, "mpatch: Unable to write to patch file");
    return false;
  }
  return ret;
}

static bool PatchSingle(
    std::ifstream &patch,
    const TempDirectory& source_dir,
    const TempDirectory& extract_dir,
    const UpdateCB& callback)
{
  delayed_source initer([&source_dir, &extract_dir, &callback]
      (const uint8_t *appdata, usize_t size) ->
        delayed_source::initializer_return
  {
    FILE *src_file = nullptr;
    auto out_file = std::make_unique<std::ofstream>();
    Xdelta3PatchHeader header;

    if (size <= sizeof(*appdata)) {
      fmt::println(std::cerr, "mpatch: patch header is too small (%d), "
          "did you use the wrong tool to create this patch?", size);
      return std::nullopt;
    }

    header = *reinterpret_cast<const Xdelta3PatchHeader*>(appdata);
    if (header.tag != PATCH_MAGIC) {
      fmt::println(std::cerr, "mpatch: not a valid patch appdata header, "
          "did you use the wrong tool to create this patch?");
      return std::nullopt;
    }

    if (size < header.out_file_off || size < header.src_file_off) {
      fmt::println(std::cerr, "mpatch: offsets out of bounds");
      return std::nullopt;
    }

    if (header.src_file_off != 0) {
      auto src_path = source_dir.path() + "/" + (char*)(appdata + header.src_file_off);
      src_file = fopen(src_path.c_str(), "r");
      if (src_file == nullptr) {
        fmt::println(std::cerr, "mpatch: Unable to open source file: {}",
            (char*)(appdata + header.src_file_off));
        return std::nullopt;
      }
    }

    callback((char*)(appdata + header.out_file_off));
    auto out_path = extract_dir.path() + "/" + (char*)(appdata + header.out_file_off);
    fs::create_directories(fs::path(out_path).parent_path());
    out_file->open(out_path.c_str());
    if (!*out_file) {
      fmt::println(std::cerr, "mpatch: Unable to open output file: {}",
          (char*)(appdata + header.out_file_off));
      return std::nullopt;
    }

    return std::optional(std::pair(src_file, std::move(out_file)));
  });

  rdbuf_section patch_buf(patch);
  std::istream section(&patch_buf);
  return XD3Entry(false, section, initer, [](auto x) {});
}

static std::optional<TempDirectory> ExtractDisk(
    const std::string &location,
    const DiscIO::Volume &volume,
    const DiscIO::CompressCB &callback,
    uint32_t *count = nullptr)
{
  auto extract_dir = TempDirectory::Create();

  fmt::println(std::cerr, "Extracting from {}...", location.c_str());
  uint32_t extract_cnt = 0;
  if (volume.GetPartitions().empty()) {
    extract_cnt += CountFiles(volume, DiscIO::PARTITION_NONE);
  } else {
    for (DiscIO::Partition &p: volume.GetPartitions()) {
      extract_cnt += CountFiles(volume, p);
    }
  }

  if (count != nullptr) {
    *count = extract_cnt;
  }

  int progress_monitor = std::max<int>(1, extract_cnt / 100);
  uint32_t extracted = 0;
  const auto extract_callback = [&callback, &extracted, extract_cnt, progress_monitor](auto text) {
    extracted += 1;
    if (extracted % progress_monitor == 0) {
      return !callback("Extracting " + text, 1.0 * std::min(extracted, extract_cnt) / extract_cnt);
    } else {
      return false;
    }
  };

  // Extract the input volume into the first directory
  if (volume.GetPartitions().empty()) {
    if (!ExtractPartition(volume, DiscIO::PARTITION_NONE, extract_dir.path(),
        extract_callback))
    {
      return std::nullopt;
    }
  } else {
    for (DiscIO::Partition &p: volume.GetPartitions()) {
      if (auto partition_type = volume.GetPartitionType(p)) {
        auto partition_name = DiscIO::NameForPartitionType(*partition_type, true);
        if (!ExtractPartition(volume, p, extract_dir.path() + "/" + partition_name,
            extract_callback))
        {
          return std::nullopt;
        }
      }
    }
  }
  callback("Finished", 1.0);

  return std::move(extract_dir);
}

static bool status_callback(const std::string& text, float percent) {
  char progress[30 + 1];
  progress[sizeof(progress) - 1] = 0;
  memset(progress, '-', sizeof(progress) - 1);
  for (int i = 0; i < (int)((sizeof(progress) - 1) * percent); i++) {
    progress[i] = '=';
  }
  fmt::print("|{}| {:.2f}% {:<50.50}\r", progress, percent * 100.0f, text.c_str());
  if (percent == 1.0) {
    fmt::println("");
  }
  return true;
}

static std::optional<TempDirectory> PatchDisc(
    const DiscIO::Volume &volume,
    const std::string &patch,
    const DiscIO::CompressCB &callback)
{
  auto extract_dir = OTRY(ExtractDisk("source", volume,
        [&callback](auto text, auto percent) {
          return callback(text, percent);
        }));
  auto out_dir = TempDirectory::Create();

  // Slowly go through the patch
  std::ifstream patch_file(patch.c_str());
  if (!patch_file) {
    fmt::println(std::cerr, "mpatch: Unable to open source file: {}",
        patch.c_str());
    return std::nullopt;
  }

  if (!patch_file.seekg(0, std::ios_base::seekdir::_S_end)) {
    fmt::println(std::cerr, "mpatch: Unable to determine size of source file: {}",
        patch.c_str());
    return std::nullopt;
  }

  uint32_t file_size = patch_file.tellg();
  if (!patch_file.seekg(0)) {
    fmt::println(std::cerr, "mpatch: Unable to reset pos: {}", patch.c_str());
    return std::nullopt;
  }

  fmt::println("Patching files...");
  auto markers = std::max(file_size / 100u, 1u);
  auto next_marker = 0u;
  patch_file.peek(); // Need to ensure that the eof/bad flags get updated
  while (!patch_file.eof()) {
    uint32_t cur_pos = patch_file.tellg();
    if (!PatchSingle(patch_file, extract_dir, out_dir,
          [markers, &next_marker, file_size, cur_pos](auto file) {
            // If this current status reaches the next marker milestone, update the
            // progress ticker
            if (next_marker <= cur_pos) {
              next_marker = ((cur_pos + markers - 1) / markers) * markers;
              return status_callback("Patching " + file,
                  (float)cur_pos / file_size);
            } else {
              return false;
            }
          }))
    {
      return std::nullopt;
    }


    patch_file.peek(); // Need to ensure that the eof/bad flags get updated
    if (patch_file.bad()) {
      fmt::println(std::cerr, "mpatch: Bad patch file!");
      return std::nullopt;
    }
  }
  status_callback("Finished", 1.0);

  // TODO: make sure this is not deleted?
  return out_dir;
}

static std::string FixInputPath(const std::string &file) {
  std::string ret;
  if (fs::is_directory(file)) {
    if (!fs::is_regular_file(file + "/sys/main.dol")) {
      fmt::print(std::cerr, "\"{}\" is a directory but can't find ./sys/main.dol",
          file.c_str());
    } else {
      ret = file + "/sys/main.dol";
    }
  } else {
    ret = file;
  }
  return ret;
}

static int ApplyPatch(const optparse::Values& options,
    const std::string &patch_file_path,
    const std::string &source_path,
    const std::string &compare_path)
{
  // --format
  const std::optional<DiscIO::BlobType> format_o = ParseFormatString(options["format"]);
  const DiscIO::BlobType format = format_o.value_or(DiscIO::BlobType::RVZ);

  // --scrub
  const bool scrub = static_cast<bool>(options.get("scrub"));

  // Open the blob reader
  std::unique_ptr<DiscIO::BlobReader> blob_reader = DiscIO::CreateBlobReader(source_path);
  if (!blob_reader)
  {
    fmt::print(std::cerr, "mpatch: The source file could not be opened.\n");
    return EXIT_FAILURE;
  }


  // Open the volume
  std::unique_ptr<DiscIO::Volume> volume = DiscIO::CreateDisc(source_path);
  if (!volume) {
    if (scrub) {
      fmt::print(std::cerr, "mpatch: Error: Scrubbing is only supported for GC/Wii disc images.\n");
      return EXIT_FAILURE;
    }

    fmt::print(std::cerr,
               "Warning: The input file is not a GC/Wii disc image. Continuing anyway.\n");
  }

  if (scrub) {
    if (volume->IsDatelDisc()) {
      fmt::print(std::cerr, "Error: Scrubbing a Datel disc is not supported.\n");
      return EXIT_FAILURE;
    }

    blob_reader = DiscIO::ScrubbedBlob::Create(source_path);

    if (!blob_reader) {
      fmt::print(std::cerr, "Error: Unable to process disc image. Try again without --scrub.\n");
      return EXIT_FAILURE;
    }
  }

  if (scrub && format == DiscIO::BlobType::RVZ) {
    fmt::print(std::cerr, "Warning: Scrubbing an RVZ container does not offer significant space "
                          "advantages. Continuing anyway.\n");
  }

  if (scrub && format == DiscIO::BlobType::PLAIN) {
    fmt::print(std::cerr, "Warning: Scrubbing does not save space when converting to ISO unless "
                          "using external compression. Continuing anyway.\n");
  }

  if (!scrub && format == DiscIO::BlobType::GCZ && volume &&
      volume->GetVolumeType() == DiscIO::Platform::WiiDisc && !volume->IsDatelDisc())
  {
    fmt::print(std::cerr, "Warning: Converting Wii disc images to GCZ without scrubbing may not "
                          "offer space advantages over ISO. Continuing anyway.\n");
  }

  if (volume && volume->IsNKit())
  {
    fmt::print(std::cerr,
               "Warning: Converting an NKit file, output will still be NKit! Continuing anyway.\n");
  }

  // --block_size
  std::optional<int> block_size_o;
  if (options.is_set("block_size"))
    block_size_o = static_cast<int>(options.get("block_size"));

  if (format == DiscIO::BlobType::GCZ || format == DiscIO::BlobType::WIA ||
      format == DiscIO::BlobType::RVZ)
  {
    if (!block_size_o.has_value())
    {
      fmt::print(std::cerr, "Error: Block size must be set for GCZ/RVZ/WIA\n");
      return EXIT_FAILURE;
    }

    if (!DiscIO::IsDiscImageBlockSizeValid(block_size_o.value(), format))
    {
      fmt::print(std::cerr, "Error: Block size is not valid for this format\n");
      return EXIT_FAILURE;
    }

    if (block_size_o.value() < DiscIO::PREFERRED_MIN_BLOCK_SIZE ||
        block_size_o.value() > DiscIO::PREFERRED_MAX_BLOCK_SIZE)
    {
      fmt::print(std::cerr,
                 "Warning: Block size is not ideal for performance. Continuing anyway.\n");
    }

    if (format == DiscIO::BlobType::GCZ && volume &&
        !DiscIO::IsGCZBlockSizeLegacyCompatible(block_size_o.value(), volume->GetDataSize()))
    {
      fmt::print(std::cerr,
                 "Warning: For GCZs to be compatible with Dolphin < 5.0-11893, the file size "
                 "must be an integer multiple of the block size and must not be an integer "
                 "multiple of the block size multiplied by 32. Continuing anyway.\n");
    }
  }

  // --compress, --compress_level
  std::optional<DiscIO::WIARVZCompressionType> compression_o =
      ParseCompressionTypeString(options["compression"]);

  std::optional<int> compression_level_o;
  if (options.is_set("compression_level"))
    compression_level_o = static_cast<int>(options.get("compression_level"));

  if (format == DiscIO::BlobType::WIA || format == DiscIO::BlobType::RVZ) {
    if (!compression_o.has_value()) {
      fmt::print(std::cerr, "Error: Compression format must be set for WIA or RVZ\n");
      return EXIT_FAILURE;
    }

    if ((format == DiscIO::BlobType::WIA &&
         compression_o.value() == DiscIO::WIARVZCompressionType::Zstd) ||
        (format == DiscIO::BlobType::RVZ &&
         compression_o.value() == DiscIO::WIARVZCompressionType::Purge))
    {
      fmt::print(std::cerr, "Error: Compression type is not supported for the container format\n");
      return EXIT_FAILURE;
    }

    if (compression_o.value() == DiscIO::WIARVZCompressionType::None) {
      compression_level_o = 0;
    } else {
      if (!compression_level_o.has_value()) {
        fmt::print(std::cerr,
                   "Error: Compression level must be set when compression type is not 'none'\n");
        return EXIT_FAILURE;
      }

      const std::pair<int, int> range =
          DiscIO::GetAllowedCompressionLevels(compression_o.value(), false);
      if (compression_level_o.value() < range.first || compression_level_o.value() > range.second)
      {
        fmt::print(std::cerr, "Error: Compression level not in acceptable range\n");
        return EXIT_FAILURE;
      }
    }
  }

  // Apply patch on temp directory
  auto tmp_disc = PatchDisc(*volume, patch_file_path, status_callback);
  if (!tmp_disc) {
    return EXIT_FAILURE;
  }

  blob_reader = DiscIO::CreateBlobReader(tmp_disc->path() + "/sys/main.dol");

  // Perform the conversion
  bool success = false;
  fmt::println("Creating output file...");
  switch (format) {
    case DiscIO::BlobType::PLAIN:
    {
      success = DiscIO::ConvertToPlain(blob_reader.get(), source_path,
          compare_path, status_callback);
      break;
    }

    case DiscIO::BlobType::GCZ:
    {
      u32 sub_type = std::numeric_limits<u32>::max();
      if (volume)
      {
        if (volume->GetVolumeType() == DiscIO::Platform::GameCubeDisc)
          sub_type = 0;
        else if (volume->GetVolumeType() == DiscIO::Platform::WiiDisc)
          sub_type = 1;
      }
      success = DiscIO::ConvertToGCZ(blob_reader.get(), source_path,
          compare_path, sub_type, block_size_o.value(), status_callback);
      break;
    }

    case DiscIO::BlobType::WIA:
    case DiscIO::BlobType::RVZ:
    {
      success = DiscIO::ConvertToWIAOrRVZ(blob_reader.get(), source_path,
          compare_path, format == DiscIO::BlobType::RVZ, compression_o.value(),
          compression_level_o.value(), block_size_o.value(), status_callback);
      break;
    }

    default:
    {
      ASSERT(false);
      break;
    }
  }
  status_callback("Finished", 1.0);

  if (!success) {
    fmt::print(std::cerr, "mpatch: Conversion failed\n");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

static int MakePatch(const std::string &patch_file_path,
    const std::string &source_path,
    const std::string &compare_path)
{
  auto source_volume = DiscIO::CreateVolume(source_path);
  if (!source_volume)
  {
    fmt::print(std::cerr, "mpatch: The source file could not be opened.\n");
    return EXIT_FAILURE;
  }
  auto compare_volume = DiscIO::CreateVolume(compare_path);
  if (!compare_volume)
  {
    fmt::print(std::cerr, "mpatch: The input file could not be opened.\n");
    return EXIT_FAILURE;
  }

  // Extract to temporary directories
  uint32_t source_files = 0;
  uint32_t compare_files = 0;
  auto source_tmp_path = ExtractDisk("source", *source_volume, status_callback, &source_files);
  if (!source_tmp_path) {
    return EXIT_FAILURE;
  }
  auto compare_tmp_path = ExtractDisk("input disk", *compare_volume, status_callback, &compare_files);
  if (!compare_tmp_path) {
    return EXIT_FAILURE;
  }
  std::unordered_map<std::string, std::string> file_lookups;

  fmt::println(std::cerr, "Checking files...");
  uint32_t status = 0;
  for (auto file: fs::recursive_directory_iterator(source_tmp_path->path())) {
    if (file.is_regular_file()) {
      auto hash = FileHash(file.path());
      auto rel_path = fs::relative(file.path(), source_tmp_path->path());
      if (!hash) {
        fmt::println(std::cerr, "mpatch: Failed to hash {}", file.path().c_str());
        return EXIT_FAILURE;
      }

      file_lookups.insert(std::pair(*hash, rel_path));
      status_callback("Checking " + rel_path.string(), ((float)status++ / source_files));
    }
  }
  status_callback("Finished", 1.0);

  fmt::println(std::cerr, "Writing patch...");
  std::ofstream patch_file(patch_file_path);
  if (!patch_file) {
    fmt::println(std::cerr, "mpatch: The patch file could not be opened for write.");
    return EXIT_FAILURE;
  }

  status = 0;
  for (auto file: fs::recursive_directory_iterator(source_tmp_path->path())) {
    if (file.is_regular_file()) {
      auto rel_path = fs::relative(file.path(), source_tmp_path->path());
      auto rel_path_str = rel_path.string();
      status_callback("Patching " + rel_path.string(), ((float)status++ / source_files));
      auto ret = WritePatch(patch_file, *source_tmp_path, *compare_tmp_path,
          rel_path_str, file_lookups);
      if (!ret) {
        return EXIT_FAILURE;
      }
    }
  }
  status_callback("Finished", 1.0);

  return 0;
}

int PatchCommand(const std::vector<std::string>& args) {
  optparse::OptionParser parser;

  parser.usage("usage: mpatch [options]... [FILE]...");

  parser.add_option("-s", "--source")
      .type("string")
      .action("store")
      .help("Path to source disc image FILE to base patching from.")
      .metavar("FILE");

  parser.add_option("-i", "--input")
      .type("string")
      .action("store")
      .help("Path to the input FILE or directory to create a patch for. "
          "Choose only either -i or -o options")
      .metavar("FILE");

  parser.add_option("-o", "--output")
      .type("string")
      .action("store")
      .help("Path to the destination FILE to create the patched image. "
          "Choose only either -i or -o options")
      .metavar("FILE");

  parser.add_option("-p", "--patch")
      .type("string")
      .action("store")
      .help("Path to the patch FILE.")
      .metavar("FILE");

  parser.add_option("-f", "--format")
      .type("string")
      .action("store")
      .help("Container format to use. Defaults to rvz. [%choices]")
      .choices({"iso", "gcz", "wia", "rvz"});

  parser.add_option("--scrub")
      .action("store_true")
      .help("Scrub junk data as part of conversion.");

  parser.add_option("-b", "--block_size")
      .type("int")
      .action("store")
      .help("Block size for GCZ/WIA/RVZ formats, as an integer. Suggested value for RVZ: 131072 "
            "(128 KiB)");

  parser.add_option("-c", "--compression")
      .type("string")
      .action("store")
      .help("Compression method to use when converting to WIA/RVZ. Suggested value for RVZ: zstd "
            "[%choices]")
      .choices({"none", "zstd", "bzip", "lzma", "lzma2"});

  parser.add_option("-l", "--compression_level")
      .type("int")
      .action("store")
      .help("Level of compression for the selected method. Ignored if 'none'. Suggested value for "
            "zstd: 5");

  const optparse::Values& options = parser.parse_args(args);

  // Validate options

  // --source
  if (!options.is_set("source"))
  {
    fmt::print(std::cerr, "mpatch: No source set\n");
    return EXIT_FAILURE;
  }
  std::string source_path = FixInputPath(options["source"]);
  if (source_path.empty()) {
    return EXIT_FAILURE;
  }

  // --output / --input
  bool creating_patch = false;
  std::string compare_path;
  if (options.is_set("output")) {
    if (options.is_set("input")) {
      fmt::print(std::cerr, "mpatch: Cannot set both -i and -o options\n");
      return EXIT_FAILURE;
    }
    compare_path = options["output"];
  } else if (options.is_set("input")) {
    creating_patch = true;
    compare_path = FixInputPath(options["input"]);
    if (compare_path.empty()) {
      return EXIT_FAILURE;
    }
  } else {
    fmt::print(std::cerr, "mpatch: No input nor output set\n");
    return EXIT_FAILURE;
  }

  // --patch
  if (!options.is_set("patch"))
  {
    fmt::print(std::cerr, "mpatch: No patch set\n");
    return EXIT_FAILURE;
  }
  const std::string& patch_file_path = options["patch"];

  if (creating_patch) {
    if (options.is_set("format")) {
      fmt::print(std::cerr, "mpatch: Warning: -f has no effect on -i mode");
    }
    if (options.is_set("scrub")) {
      fmt::print(std::cerr, "mpatch: Warning: --scrub has no effect on -i mode");
    }
    if (options.is_set("block_size")) {
      fmt::print(std::cerr, "mpatch: Warning: -b has no effect on -i mode");
    }
    if (options.is_set("block_size")) {
      fmt::print(std::cerr, "mpatch: Warning: -b has no effect on -i mode");
    }
    if (options.is_set("compression")) {
      fmt::print(std::cerr, "mpatch: Warning: -c has no effect on -i mode");
    }
    if (options.is_set("compression_level")) {
      fmt::print(std::cerr, "mpatch: Warning: -l has no effect on -i mode");
    }
  }

  // Open the blob reader

  if (!creating_patch) {
    return ApplyPatch(options, patch_file_path, source_path, compare_path);
  } else {
    return MakePatch(patch_file_path, source_path, compare_path);
  }
}

}  // namespace DolphinTool
