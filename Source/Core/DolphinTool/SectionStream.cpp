#include "SectionStream.h"
#include <cstring>

namespace DolphinTool {

void section_streambuf::create_buffer(std::streamsize sz) {
  if (m_buffer) {
    delete[] m_buffer;
  }
  if (sz < 0) {
    m_buffer = nullptr;
  } else {
    this->m_buffer = new char[sz];
    this->m_buffer_sz = sz;
  }
}

void section_streambuf::set_buffer(std::streamsize off) {
  const bool testin = m_mode & std::ios_base::in;
  const bool testout = (m_mode & std::ios_base::out
                          || m_mode & std::ios_base::app);

  if (m_buffer == nullptr) {
    this->setg(0, 0, 0);
    this->setp(0, 0);
    return;
  }

  if (testin && off > 0)
    this->setg(m_buffer, m_buffer, m_buffer + off);
  else
    this->setg(m_buffer, m_buffer, m_buffer);

  if (testout && off == 0 && m_buffer_sz > 1 )
    this->setp(m_buffer, m_buffer + m_buffer_sz - 1);
  else
    this->setp(0, 0);
}

rdbuf_section::rdbuf_section(std::istream &underlying): section_streambuf(underlying.rdbuf(), std::ios_base::in),
  m_bad(false)
{
  if (this->underlying()->sgetn((char*)&m_left, sizeof(m_left)) != sizeof(m_left)) {
    m_bad = true;
  }

  this->create_buffer(0x1000);
}

rdbuf_section::int_type rdbuf_section::underflow() {
  if (m_bad || m_left == 0) {
    return traits_type::eof();
  }

  if (this->gptr() < this->egptr())
    return traits_type::to_int_type(*this->gptr());

  // TODO: what if there is no buffer
  this->set_buffer(-1);
  auto read = this->underlying()->sgetn(this->gptr(),
      (std::streamsize)std::min<size_t>(this->buffer_sz(), m_left));
  this->set_buffer(read);
  if (read <= 0) {
    m_bad = true;
    return traits_type::eof();
  } else {
    m_left -= read;
    return traits_type::to_int_type(*this->gptr());
  }
}

enum wrbuf_state {
  good = 0,
  bad = (1<<0),
  syncing = (1<<1),
};


int wrbuf_section::write_written(bool repos) {
  pos_type cur_pos;
  if (repos) {
      cur_pos = this->underlying()->pubseekoff(0, std::ios_base::cur, std::ios_base::out);
      this->underlying()->pubseekpos(m_offset, std::ios_base::out);
  }

  if (this->underlying()->sputn((char*)&m_written, sizeof(m_written)) != sizeof(m_written)) {
    m_state |= wrbuf_state::bad;
    return -1;
  }

  if (this->underlying()->pubsync() < 0) {
    m_state |= wrbuf_state::bad;
    return -1;
  }

  if (repos) {
    this->underlying()->pubseekpos(cur_pos, std::ios_base::out);
  }
  return 0;
}

wrbuf_section::wrbuf_section(std::ostream &underlying): section_streambuf(underlying.rdbuf(), std::ios_base::out),
  m_offset(0), m_written(0), m_state(wrbuf_state::good)
{
  m_offset = this->underlying()->pubseekoff(0, std::ios_base::cur, std::ios_base::out);
  if (m_offset < 0) {
    m_state |= wrbuf_state::bad;
    return;
  }

  if (this->write_written() < 0) {
    return;
  }

  this->create_buffer(0x1000);
}

wrbuf_section::int_type wrbuf_section::overflow(int_type c) {
  if (m_state & wrbuf_state::bad) {
    return traits_type::eof();
  }

  const bool test_eof = traits_type::eq_int_type(c, traits_type::eof());
  std::streamsize written = 0;
        if (this->pbase() < this->pptr()) {
    // Push to the underlying buffer
    auto buff_sz = this->pptr() - this->pbase();
    written = this->underlying()->sputn(this->pbase(), buff_sz);
    if (this->underlying()->pubsync() < 0) {
      m_state |= wrbuf_state::bad;
      return traits_type::eof();
    }

    m_written += written;
    if (this->write_written(true) < 0) {
      return traits_type::eof();
    }

    if (written == buff_sz) {
      this->set_buffer(0);
    } else {
      memmove(this->buffer(), this->pptr(), written - buff_sz);
      this->set_buffer(written - buff_sz);
    }

    if (written == 0) {
      m_state |= wrbuf_state::bad;
      return traits_type::eof();
    }
  } else if (this->buffer_sz() > 0) {
    // We've resetted the buffer
    this->set_buffer(0);
    written = 1;
  }

  // Append the overflow character
  if (!test_eof) {
    *this->pptr() = traits_type::to_char_type(c);
    this->pbump(1);
  }

  return traits_type::not_eof(c);
}

int wrbuf_section::sync() {
  int ret = 0;
  if (this->pbase() < this->pptr()) {
    auto tmp = this->overflow();
    if (traits_type::eq_int_type(tmp, traits_type::eof())) {
      ret = -1;
    }
  }

  return ret;
}

}
