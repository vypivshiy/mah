use crate::dumper::{
    DumpResult, EventEntry, ModelEntry, PacketEntry, PolymorphicModelEntry, PolymorphicVariant,
    TypeDescriptorEntry,
};
use crate::extractor::ExtractedField;
use std::fmt::Write;

pub fn format_compact_dump(dump: &DumpResult) -> String {
    let mut out = String::new();

    writeln!(out, "app_version: {}", dump.options.version).unwrap();
    writeln!(out, "build_number: {}", dump.options.build).unwrap();

    write_packets(&mut out, &dump.packets);
    write_events(&mut out, &dump.events);
    write_models(&mut out, &dump.models);
    write_polymorphic_models(&mut out, &dump.polymorphic_models);
    write_string_enums(&mut out, &dump.string_enums);

    out
}

fn write_packets(out: &mut String, packets: &[PacketEntry]) {
    writeln!(out).unwrap();
    writeln!(out, "Packets").unwrap();

    let mut packets: Vec<_> = packets.iter().collect();
    packets.sort_by(|a, b| {
        a.opcode
            .cmp(&b.opcode)
            .then_with(|| a.request.name.cmp(&b.request.name))
            .then_with(|| a.response.name.cmp(&b.response.name))
    });

    for packet in packets {
        writeln!(out, "packet opcode={}", packet.opcode).unwrap();
        write_type_entry(out, "  request", &packet.request);
        write_type_entry(out, "  response", &packet.response);
    }
}

fn write_events(out: &mut String, events: &[EventEntry]) {
    writeln!(out).unwrap();
    writeln!(out, "Events").unwrap();

    let mut events: Vec<_> = events.iter().collect();
    events.sort_by(|a, b| {
        a.opcode
            .cmp(&b.opcode)
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| option_entry_name(&a.request).cmp(option_entry_name(&b.request)))
            .then_with(|| option_entry_name(&a.response).cmp(option_entry_name(&b.response)))
    });

    for event in events {
        writeln!(out, "event opcode={}", event.opcode).unwrap();
        if let Some(kind) = &event.kind {
            writeln!(out, "  kind: {kind}").unwrap();
        }
        if let Some(name) = &event.name {
            writeln!(out, "  name: {name}").unwrap();
        }
        if let Some(base_kind) = &event.base_kind {
            writeln!(out, "  base_kind: {base_kind}").unwrap();
        }
        if let Some(offset) = &event.offset {
            writeln!(out, "  rva: {offset}").unwrap();
        }
        if let Some(warn) = &event.warn {
            writeln!(out, "  warn: {warn}").unwrap();
        }
        if let Some(request) = &event.request {
            write_type_entry(out, "  request", request);
        }
        if let Some(response) = &event.response {
            write_type_entry(out, "  response", response);
        }
    }
}

fn write_models(out: &mut String, models: &[ModelEntry]) {
    writeln!(out).unwrap();
    writeln!(out, "Models").unwrap();

    let mut models: Vec<_> = models.iter().collect();
    models.sort_by(|a, b| a.name.cmp(&b.name));

    for model in models {
        write_model_entry(out, model);
    }
}

fn write_polymorphic_models(out: &mut String, models: &[PolymorphicModelEntry]) {
    writeln!(out).unwrap();
    writeln!(out, "Polymorphic Models").unwrap();

    let mut models: Vec<_> = models.iter().collect();
    models.sort_by(|a, b| a.name.cmp(&b.name));

    for model in models {
        writeln!(out, "polymorphic {}", model.name).unwrap();
        write_sorted_values(out, "  root_sources", &model.root_sources);
        if let Some(discriminator) = &model.discriminator {
            writeln!(
                out,
                "  discriminator: {}: {}",
                discriminator.field, discriminator.r#type
            )
            .unwrap();
        }
        write!(out, "  base").unwrap();
        write_optional_rva(out, &model.base.offset);
        writeln!(out, " fields={}", model.base.fields.len()).unwrap();
        write_variants(out, "  variant", &model.variants);
        write_variants(out, "  rtti_subclass", &model.rtti_subclasses);
    }
}

fn write_string_enums(out: &mut String, string_enums: &[String]) {
    writeln!(out).unwrap();
    writeln!(out, "String Enums").unwrap();

    let mut string_enums = string_enums.to_vec();
    string_enums.sort();

    for string_enum in string_enums {
        writeln!(out, "string_enum {string_enum}").unwrap();
    }
}

fn write_type_entry(out: &mut String, label: &str, entry: &TypeDescriptorEntry) {
    write!(out, "{label} {}", entry.name).unwrap();
    write_optional_rva(out, &entry.offset);
    writeln!(out).unwrap();

    if let Some(warn) = &entry.warn {
        writeln!(out, "{label} warn: {warn}").unwrap();
    }
    for field in &entry.fields {
        writeln!(
            out,
            "{label} field {}: {}",
            field.name, field.field_type.full
        )
        .unwrap();
    }
}

fn write_model_entry(out: &mut String, model: &ModelEntry) {
    write!(out, "model {}", model.name).unwrap();
    write_optional_rva(out, &model.offset);
    writeln!(out).unwrap();

    if let Some(warn) = &model.warn {
        writeln!(out, "  warn: {warn}").unwrap();
    }
    for field in &model.fields {
        write_field(out, field);
    }
}

fn write_field(out: &mut String, field: &ExtractedField) {
    writeln!(out, "  field {}: {}", field.name, field.field_type.full).unwrap();
}

fn write_variants(out: &mut String, label: &str, variants: &[PolymorphicVariant]) {
    let mut variants: Vec<_> = variants.iter().collect();
    variants.sort_by(|a, b| a.name.cmp(&b.name));

    for variant in variants {
        write!(out, "{label} {}", variant.name).unwrap();
        write_optional_rva(out, &variant.offset);
        write!(
            out,
            " local_fields={} all_fields={}",
            variant.fields.len(),
            variant.all_fields.len()
        )
        .unwrap();
        if let Some(tag) = &variant.tag {
            write!(out, " tag={tag}").unwrap();
        }
        writeln!(out).unwrap();
    }
}

fn write_sorted_values(out: &mut String, label: &str, values: &[String]) {
    let mut values = values.to_vec();
    values.sort();
    writeln!(out, "{label}: {}", values.join(", ")).unwrap();
}

fn write_optional_rva(out: &mut String, offset: &Option<String>) {
    if let Some(offset) = offset {
        write!(out, " rva={offset}").unwrap();
    }
}

fn option_entry_name(entry: &Option<TypeDescriptorEntry>) -> &str {
    entry
        .as_ref()
        .map(|entry| entry.name.as_str())
        .unwrap_or("")
}
