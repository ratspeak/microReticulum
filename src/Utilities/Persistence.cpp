#include "Persistence.h"

#include "Bytes.h"

using namespace RNS;

#if defined(BOARD_HAS_PSRAM) && defined(ESP32)
/*static*/ RNS::Persistence::PsramAllocator _psramAllocatorImpl;
/*static*/ JsonDocument _document(&_psramAllocatorImpl);
#else
/*static*/ //DynamicJsonDocument _document(Type::Persistence::DOCUMENT_MAXSIZE);
/*static*/ JsonDocument _document;
#endif
/*static*/ Bytes _buffer(Type::Persistence::BUFFER_MAXSIZE);
