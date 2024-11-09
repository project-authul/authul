use uuid::Uuid;

use authul_macros::authul_table;

#[authul_table]
#[derive(Debug)]
pub struct Principal {
	id: Uuid,
}
