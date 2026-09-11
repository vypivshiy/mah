# MAX Desktop Protocol & Dumper

Domain model and terminology for the desktop client protocol reverse-engineering and autonomous dumper tooling.

## Language

**Packet**:
A structured bidirectional RPC message transmitted over the TCP/TLS connection, identified by a 16-bit opcode in a 10-byte fixed transport header.
_Avoid_: Message, Frame, Request

**Event**:
A server-push notification payload received asynchronously without an initiating client request opcode.
_Avoid_: Notification, Push, Signal

**Model**:
A serializable C++ struct schema representing request/response payloads, nested entities, or domain objects.
_Avoid_: Struct, DTO, Class

**Polymorphic Model**:
A model hierarchy consisting of an abstract base type and multiple concrete variant types, discriminated at runtime by a string `_type` field.
_Avoid_: Interface, Union, Dynamic Struct

**SerializableMember**:
An internal C++ template type (`Serialization::SerializableMember<T>`) used by the client binary to reflect and bind struct fields, types, and required/optional validation flags.
_Avoid_: Field Descriptor, Member Binding
