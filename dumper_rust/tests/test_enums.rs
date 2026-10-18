use std::fs;

use dumper_rust::datamining::{
    extract_static_enum_tables, extract_static_enums, EnumTableForm,
};
use dumper_rust::pe::PeImage;

mod common;
use common::resolve_core_dll;

#[test]
fn test_core_dll_static_enum_tables_extraction() {
    let dll_path = match resolve_core_dll() {
        Some(path) => path,
        None => {
            eprintln!("Skipping integration test: CORE_DLL_PATH not found");
            return;
        }
    };

    let bytes = fs::read(&dll_path).expect("Failed to read core.dll");
    let pe = PeImage::parse(&bytes).expect("Failed to parse core.dll PE image");

    // 1. Extract raw discovered tables with metadata
    let tables = extract_static_enum_tables(&pe);
    assert_eq!(tables.len(), 3, "Expected 3 static enum tables");

    // Check ServerErrorCodes
    let sec_table = tables
        .iter()
        .find(|t| t.category == "ServerErrorCodes")
        .expect("ServerErrorCodes table must be discovered");
    assert_eq!(sec_table.form, EnumTableForm::StringKeyFirst);
    assert_eq!(sec_table.rva_start, 0x18e2730);
    assert_eq!(sec_table.rva_end, 0x18e2808);
    assert_eq!(sec_table.entries.len(), 9);

    // Check UserSettings
    let us_table = tables
        .iter()
        .find(|t| t.category == "UserSettings")
        .expect("UserSettings table must be discovered");
    assert_eq!(us_table.form, EnumTableForm::ValueFirst);
    assert_eq!(us_table.rva_start, 0x195f550);
    assert_eq!(us_table.rva_end, 0x195f7f0);
    assert_eq!(us_table.entries.len(), 28);

    // Check CallProblems
    let cp_table = tables
        .iter()
        .find(|t| t.category == "CallProblems")
        .expect("CallProblems table must be discovered");
    assert_eq!(cp_table.form, EnumTableForm::ValueFirst);
    assert_eq!(cp_table.rva_start, 0x18f9870);
    assert_eq!(cp_table.rva_end, 0x18f9960);
    assert_eq!(cp_table.entries.len(), 10);

    // 2. Extract typed catalog (category -> name -> u64)
    let catalog = extract_static_enums(&pe);
    assert_eq!(catalog.len(), 3);

    // Verify ServerErrorCodes entries
    let server_errors = &catalog["ServerErrorCodes"];
    assert_eq!(server_errors.get("call.blocked"), Some(&6));
    assert_eq!(server_errors.get("privacy.violation"), Some(&5));
    assert_eq!(server_errors.get("limit.reached"), Some(&7));
    assert_eq!(server_errors.get("user.restricted.call"), Some(&8));
    assert_eq!(server_errors.get("user.blocked"), Some(&9));
    assert_eq!(server_errors.get("edit.not.allowed"), Some(&11));
    assert_eq!(server_errors.get("not.chat.participant"), Some(&3));
    assert_eq!(server_errors.get("not.admin"), Some(&12));
    assert_eq!(server_errors.get("wait.for.admin"), Some(&4));

    // Verify UserSettings entries
    let user_settings = &catalog["UserSettings"];
    assert_eq!(user_settings.get("userSettings/showReadmark"), Some(&0));
    assert_eq!(user_settings.get("userSettings/incomingCall"), Some(&1));
    assert_eq!(user_settings.get("userSettings/chatInvite"), Some(&2));
    assert_eq!(user_settings.get("userSettings/hidden"), Some(&3));
    assert_eq!(user_settings.get("userSettings/safeMode"), Some(&4));
    assert_eq!(user_settings.get("userSettings/searchByPhone"), Some(&5));
    assert_eq!(user_settings.get("userSettings/unsafeFilesAlert"), Some(&6));
    assert_eq!(user_settings.get("userSettings/contentLevelAccess"), Some(&7));
    assert_eq!(user_settings.get("userSettings/familyProtection"), Some(&8));
    assert_eq!(user_settings.get("userSettings/phoneNumberPrivacy"), Some(&9));
    assert_eq!(user_settings.get("userSettings/pushNewContacts"), Some(&10));
    assert_eq!(
        user_settings.get("statistic/statisticPresenceOnlineContactOpenedCounter"),
        Some(&11)
    );
    assert_eq!(
        user_settings.get("statistic/statisticPresenceOnlineContactClosedCounter"),
        Some(&12)
    );
    assert_eq!(
        user_settings.get("statistic/statisticPresenceOnlineStrangerOpenedCounter"),
        Some(&13)
    );
    assert_eq!(
        user_settings.get("statistic/statisticPresenceOnlineStrangerClosedCounter"),
        Some(&14)
    );
    assert_eq!(
        user_settings.get("statistic/statisticPresenceOfflineContactOpenedCounter"),
        Some(&15)
    );
    assert_eq!(
        user_settings.get("statistic/statisticPresenceOfflineContactClosedCounter"),
        Some(&16)
    );
    assert_eq!(
        user_settings.get("statistic/statisticPresenceOfflineStrangerOpenedCounter"),
        Some(&17)
    );
    assert_eq!(
        user_settings.get("statistic/statisticPresenceOfflineStrangerClosedCounter"),
        Some(&18)
    );
    assert_eq!(
        user_settings.get("notifications/notificationSilentMode"),
        Some(&19)
    );
    assert_eq!(user_settings.get("notifications/p2pEnabled"), Some(&20));
    assert_eq!(user_settings.get("notifications/p2gEnabled"), Some(&21));
    assert_eq!(
        user_settings.get("notifications/p2gRepliesOnly"),
        Some(&22)
    );
    assert_eq!(
        user_settings.get("notifications/channelsEnabled"),
        Some(&23)
    );
    assert_eq!(
        user_settings.get("notifications/channelCommentsLevel"),
        Some(&24)
    );
    assert_eq!(user_settings.get("notifications/textVisible"), Some(&25));
    assert_eq!(user_settings.get("notifications/muteInCalls"), Some(&26));
    assert_eq!(
        user_settings.get("userAppearance/messageFontSize"),
        Some(&27)
    );

    // Verify CallProblems entries
    let call_problems = &catalog["CallProblems"];
    assert_eq!(call_problems.get("AUDIO_FREEZES"), Some(&1));
    assert_eq!(call_problems.get("AUDIO_CALL_INTERRUPTION"), Some(&2));
    assert_eq!(call_problems.get("VOICE_COMMUNICATION_PROBLEM"), Some(&3));
    assert_eq!(call_problems.get("AUDIO_QUALITY"), Some(&4));
    assert_eq!(call_problems.get("AUDIO_ECHO"), Some(&5));
    assert_eq!(call_problems.get("VIDEO_FREEZES"), Some(&6));
    assert_eq!(call_problems.get("VIDEO_QUALITY"), Some(&7));
    assert_eq!(call_problems.get("VIDEO_SYNC"), Some(&8));
    assert_eq!(call_problems.get("VIDEO_CALL_INTERRUPTION"), Some(&9));
    assert_eq!(call_problems.get("USERS_FREEZES"), Some(&10));
}
