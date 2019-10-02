/*
 * Copyright 2019 Google, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met: redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer;
 * redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution;
 * neither the name of the copyright holders nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Authors: Gabe Black
 */

#ifndef __ARCH_ARM_FASTMODEL_COMMON_SIGNAL_RECEIVER_HH__
#define __ARCH_ARM_FASTMODEL_COMMON_SIGNAL_RECEIVER_HH__

#include <amba_pv.h>
#include <functional>

namespace FastModel
{

class SignalReceiver : public amba_pv::signal_slave_base<bool>
{
  public:
    typedef std::function<void(bool)> OnChangeFunc;

  private:
    bool _state;
    OnChangeFunc _onChange;

  public:
    amba_pv::signal_slave_export<bool> signal_in;

    SignalReceiver(const char *name) : SignalReceiver(name, nullptr) {}

    SignalReceiver(const char *name, OnChangeFunc on_change) :
        amba_pv::signal_slave_base<bool>(name),
        _state(false), _onChange(on_change)
    {
        signal_in.bind(*this);
    }

    void onChange(OnChangeFunc func) { _onChange = func; }

    void
    set_state(int export_id, const bool &new_state) override
    {
        if (new_state == _state)
            return;

        _state = new_state;
        _onChange(_state);
    }
};

} // namespace FastModel

#endif // __ARCH_ARM_FASTMODEL_COMMON_SIGNAL_RECEIVER_HH__