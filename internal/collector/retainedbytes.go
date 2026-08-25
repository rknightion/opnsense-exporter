package collector

import "reflect"

const (
	maxRetainedKeyBytes    = 4096
	maxRetainedFamilyBytes = 8 << 20
)

func retainedStringBytes(values ...any) (int, bool) {
	total := 0
	var walk func(reflect.Value) bool
	walk = func(v reflect.Value) bool {
		if !v.IsValid() {
			return true
		}
		if v.Kind() == reflect.Interface || v.Kind() == reflect.Pointer {
			if v.IsNil() {
				return true
			}
			return walk(v.Elem())
		}
		switch v.Kind() {
		case reflect.String:
			if v.Len() > maxRetainedKeyBytes {
				return false
			}
			total += v.Len()
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				if !walk(v.Field(i)) {
					return false
				}
			}
		case reflect.Array, reflect.Slice:
			for i := 0; i < v.Len(); i++ {
				if !walk(v.Index(i)) {
					return false
				}
			}
		case reflect.Map:
			iter := v.MapRange()
			for iter.Next() {
				if !walk(iter.Key()) || !walk(iter.Value()) {
					return false
				}
			}
		}
		return total <= maxRetainedFamilyBytes
	}
	for _, value := range values {
		if !walk(reflect.ValueOf(value)) {
			return total, false
		}
	}
	return total, true
}
