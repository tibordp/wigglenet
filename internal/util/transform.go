package util

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// StripManagedFields removes metadata.managedFields from Kubernetes objects
// before they enter the informer cache, reducing memory usage. This implements
// cache.TransformFunc.
func StripManagedFields(obj interface{}) (interface{}, error) {
	if accessor, ok := obj.(metav1.ObjectMetaAccessor); ok {
		objectMeta := accessor.GetObjectMeta()
		if objectMeta != nil {
			objectMeta.SetManagedFields(nil)
		}
	}
	return obj, nil
}
