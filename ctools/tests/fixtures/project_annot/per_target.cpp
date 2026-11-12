// SPDX-License-Identifier: CC-BY-4.0
// Copyright (c) lemiur, TheCloakedCoder and contributors
// flags: /EHa
#include "widgets.h"

// vtable: 0x00600100 0x00600200
class Widget : public Base {
public:
    virtual ~Widget();
};

// match: 0x0078B0D0 0x007837A0
void Foo_Bar::MakeUpdate()
{
    if (ready) { step(); }
}

// match: 0x0078B100 0
// stop: the register choice differs
bool Target::Update(Foo* f, bool inside, float scale)
{
    return inside && scale > 0.0f && f != 0;
}

// match: 0x0078B180 0x00783800
// pending: R4 a fixed-offset access remains
bool Target::Update(Foo* f)
{
    return f != 0;
}

// match: 0x0078B200 0x00783900
// stop(beta): the second copy is laid out differently
Widget::~Widget()
{
}

// match: 0x0078B300 0x00783A00
template Map<Target>::~Map();

// match: 0x0078B400 0x00783B00
DataStream& DataStream::operator>>(unsigned int& value)
{
    value = ReadWord();
    return *this;
}

// match: 0x0078B400 0x00783B00
DataStream& DataStream::operator>>(float& value)
{
    value = ReadFloat();
    return *this;
}

// data: 0x00700000 0x00700010
int g_counter = 0;
