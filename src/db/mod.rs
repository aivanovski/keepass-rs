//! Types representing an opened KeePass database
//!
//! The main entry point is the [Database] struct, which can be created with [Database::new] or
//! loaded from a file using [Database::open]. The example uses explicit type annotations to show
//! what is happening, but these can be omitted in your own code.
//!
//! ```
//! use keepass::{Database, db::{fields, AttachmentMut, EntryMut, GroupMut, Value}};
//! # fn main() {
//! let mut db = Database::new();
//! let mut root: GroupMut<'_> = db.root_mut();
//!
//! // Add a new child group to the root group
//! let mut group: GroupMut<'_> = root.add_group();
//!
//! // GroupMut dereferences to &mut Group, so you can access most of its fields directly
//! group.name = "My Group".into();
//! group.notes = Some("This is an example group".into());
//!
//! // Add a new entry to the group
//! let mut entry: EntryMut<'_> = root.add_entry();
//!
//! // EntryMut dereferences to &mut Entry, so you can access most of its fields directly
//! entry.set_unprotected(fields::TITLE, "My Entry");
//! entry.set_unprotected(fields::USERNAME, "jdoe");
//! entry.set_protected(fields::PASSWORD, "hunter2");
//! entry.tags.push("example".into());
//!
//! // Adding the attachment to an entry will store it in the associated database and add a
//! // reference to the entry.
//! entry.add_attachment("myfile.txt", Value::unprotected(b"Hello, world!".to_vec()));
//!
//! // You can also use the fluent API to chain method calls together.
//! let entry_id = root.add_group()
//!     .edit(|g: &mut GroupMut| {
//!         g.name = "Another Group".into();
//!         g.notes = Some("This is another example group".into());
//!     })
//!     .add_entry()
//!     .edit(|e: &mut EntryMut<'_>| {
//!         e.set_unprotected(fields::TITLE, "Another Entry");
//!         e.set_unprotected(fields::USERNAME, "asmith");
//!         e.set_protected(fields::PASSWORD, "password123");
//!         e.tags.push("example".into());
//!     }).id();
//! # }
//! ```
pub mod fields;

mod open;
mod types;

#[cfg(feature = "_merge")]
pub mod merge;

#[cfg(feature = "totp")]
mod otp;

#[cfg(feature = "save_kdbx4")]
mod save;

#[cfg(feature = "save_kdbx4")]
pub use crate::db::save::DatabaseSaveError;

pub use crate::db::{
    open::{DatabaseFormatError, DatabaseOpenError},
    types::*,
};

#[cfg(feature = "totp")]
pub use crate::db::otp::{TOTPAlgorithm, TOTPError, TOTP};

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod database_tests {
    use std::fs::File;

    use uuid::Uuid;

    use crate::{
        config::DatabaseConfig,
        db::{DatabaseOpenError, GroupId},
        Database, DatabaseKey,
    };

    #[test]
    fn test_new_with_root_id_uses_provided_root_id() {
        let root_id = GroupId::from_uuid(Uuid::parse_str("01234567-89ab-cdef-0123-456789abcdef").unwrap());

        let db = Database::new_with_root_id(root_id);

        assert_eq!(db.root().id(), root_id);
        assert_eq!(db.config, DatabaseConfig::default());
    }

    #[test]
    fn test_with_config_and_root_id_uses_provided_root_id() {
        let root_id = GroupId::from_uuid(Uuid::parse_str("fedcba98-7654-3210-fedc-ba9876543210").unwrap());
        let config = DatabaseConfig::default();

        let db = Database::with_config_and_root_id(config.clone(), root_id);

        assert_eq!(db.root().id(), root_id);
        assert_eq!(db.config, config);
    }

    #[test]
    fn test_xml() -> Result<(), DatabaseOpenError> {
        let xml = Database::get_xml(
            &mut File::open("tests/resources/test_db_with_password.kdbx")?,
            DatabaseKey::new().with_password("demopass"),
        )?;

        assert!(xml.len() > 100);

        Ok(())
    }

    #[test]
    fn test_open_invalid_version_header_size() {
        assert!(Database::parse(&[], DatabaseKey::new().with_password("testing")).is_err());
        assert!(Database::parse(
            &[0, 0, 0, 0, 0, 0, 0, 0],
            DatabaseKey::new().with_password("testing")
        )
        .is_err());
        assert!(Database::parse(
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            DatabaseKey::new().with_password("testing")
        )
        .is_err());
    }

    #[cfg(feature = "save_kdbx4")]
    #[test]
    fn test_save() {
        use crate::format::variant_dictionary::VariantDictionary;
        let mut db = Database::new();

        let mut public_custom_data = VariantDictionary::new();
        public_custom_data.set("example", 42);

        db.config.public_custom_data = Some(public_custom_data);

        db.root_mut().add_entry();
        db.root_mut().add_entry();
        db.root_mut().add_entry();

        let mut buffer = Vec::new();

        db.save(&mut buffer, DatabaseKey::new().with_password("testing"))
            .unwrap();

        let db_loaded = Database::open(
            &mut buffer.as_slice(),
            DatabaseKey::new().with_password("testing"),
        )
        .unwrap();

        assert_eq!(db, db_loaded);
    }
}
