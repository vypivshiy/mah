"""
PATCHES.py — Manual type overrides for the Binary Ninja dumper.

When the dumper extracts types from RTTI (SerializableMember<T>),
some types may not match the actual protocol types (e.g. int32_t
instead of unsigned int or bool). Use this file to correct them.

HOW TO USE:
  1. Run the dumper once to generate packets.json
  2. Find fields with wrong types in packets.json
  3. Copy the full_name from packets.json and add an entry below
  4. Re-run the dumper — patches apply automatically

FORMAT:
  PATCHES = {
      "Api::OneMe::Packets::<Namespace>::<Type>::Response": {
          "fieldName": "correct_type",
      },
  }

  REMOVES = [
      "Api::OneMe::Packets::<Namespace>::<Type>::Response::fieldName",
  ]
"""

PATCHES = {
}

REMOVES = []
