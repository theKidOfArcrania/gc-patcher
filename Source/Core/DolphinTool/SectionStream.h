// Copyright 2024 theKidOfArcrania
// SPDX-License-Identifier: GPL-2.0-or-later

#include <ios>
#include <fstream>

namespace DolphinTool {

class section_streambuf: public std::streambuf {
private:
  std::streambuf *m_underlying;
  char *m_buffer;
  size_t m_buffer_sz;
  std::ios_base::openmode m_mode;

protected:
  section_streambuf(std::streambuf *underlying, std::ios_base::openmode mode):
    m_underlying(underlying), m_buffer(nullptr), m_buffer_sz(0), m_mode(mode)
  {
  }

  ~section_streambuf() {
    if (m_buffer) {
      delete[] m_buffer;
    }
  }

  char *buffer() const {
    return m_buffer;
  }

  size_t buffer_sz() const {
    return m_buffer_sz;
  }

  void create_buffer(std::streamsize sz);

  void set_buffer(std::streamsize off);

  std::streambuf *underlying() const {
    return this->m_underlying;
  }
};

class rdbuf_section: public section_streambuf {
private:
  uint32_t m_left;
  bool m_bad;

public:
  explicit rdbuf_section(std::istream &underlying);

protected:
  int_type underflow() override;
};

class wrbuf_section: public section_streambuf {
private:
  std::ostream::pos_type m_offset;
  uint32_t m_written;
  int m_state;

  int write_written(bool repos = false);

public:
  wrbuf_section(std::ostream &underlying);

protected:
  int_type overflow(int_type c = traits_type::eof()) override;

  int sync() override;
};

}
