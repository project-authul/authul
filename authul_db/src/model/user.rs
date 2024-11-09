use uuid::Uuid;

use authul_macros::authul_table;

#[authul_table]
#[derive(Debug)]
pub struct User {
	id: Uuid,
	#[column(find_by)]
	email: String,
	pwhash: String,
}
