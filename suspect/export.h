#pragma once

#define export_sym_c extern "C" __declspec(dllexport)

export_sym_c void hello(void);