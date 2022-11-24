package storage

func (conn *Connection) UpdateOnly(model interface{}, includeColumns ...string) error {
	return conn.UpdateColumns(model, includeColumns...)
}
