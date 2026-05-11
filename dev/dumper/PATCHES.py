"""
PATCHES.py — Manual type overrides for the binary dumper.

When the dumper extracts types from RTTI (SerializableMember<T>),
some types may not match the actual protocol types (e.g. __int64
instead of unsigned int or bool). Use this file to correct them.

HOW TO USE:
  1. Run the dumper once to generate packets.json
  2. Find fields with wrong types in packets.json
  3. Copy the full_name from packets.json and add an entry below
  4. Re-run the dumper (Alt+F7 -> run.py) — patches apply automatically
  5. No IDA restart needed — run.py reloads this module each time

FORMAT:
  PATCHES = {
      "Api::OneMe::Packets::<Namespace>::<Type>::Response": {
          "fieldName": "correct_type",
      },
  }

  REMOVES = [
      "Api::OneMe::Packets::<Namespace>::<Type>::Response::fieldName",
  ]

  - Keys in PATCHES: full_name as-is from packets.json (copy-paste)
  - Values: field_name -> corrected type string
  - REMOVES: list of "full_name::field_name" to exclude from output
"""

PATCHES = {
    # "Api::OneMe::Packets::Auth::OneMe::AuthRequest::Response": {
    #     "codeLength": "unsigned int",
    # },
    # "Api::OneMe::Packets::Auth::OneMe::CreateQr::Response": {
    #     "ttl": "std::optional<bool>",
    # },

    # я когоденераторы не покрыл на unsigned int, раскомментировать если будете патчи применять     
    # === DESKTOP dont want accept generic integer ===
    # "Api::OneMe::Packets::Auth::OneMe::AuthRequest::Response": {
    #     "codeLength": "unsigned int",
    # },
    # # === real type: bool ===
    # "Api::OneMe::Packets::Auth::OneMe::CreateQr::Response": {
    #     "ttl": "bool"
    # },
    # "Api::OneMe::Types::Message": {
    #     "ttl": "bool"
    # },
    # "Api::OneMe::Types::OutgoingMessage": {
    #     "ttl": "bool"
    # }


}

REMOVES = []  # list of "full_name::field_name" strings
