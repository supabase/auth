package storage

func (conn *Connection) UpdateOnly(model interface{}, includeColumns ...string) error {
	includeColumns = append(includeColumns, "updated_at")
	return conn.UpdateColumns(model, includeColumns...)
}
