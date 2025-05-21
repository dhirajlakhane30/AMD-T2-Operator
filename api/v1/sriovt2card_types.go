/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// SriovT2CardSpec defines the desired state of SriovT2Card
type SriovT2CardSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	NodeSelector        map[string]string   `json:"nodeSelector"`
	AcceleratorSelector AcceleratorSelector `json:"acceleratorSelector"`
	PhysicalFunction    PhysicalFunction    `json:"physicalFunction"`
	Selector            Selector            `json:"selector"`
	Template            PodTemplate         `json:"template"`
}

type Selector struct {
	MatchLabels map[string]string `json:"matchLabels"`
}
type PodTemplate struct {
	Spec PodSpec `json:"spec"`
}
type PodSpec struct {
	ImagePullSecrets []ImagePullSecrets `json:"imagePullSecrets,omitempty"`
	Containers       []ContainerSpec    `json:"containers"`
	// Volumes          []corev1.Volume    `json:"volumes"`
}

type ImagePullSecrets struct {
	Name string `json:"name"`
}

type ContainerSpec struct {
	Name            string          `json:"name"`
	Image           string          `json:"image"`
	SecurityContext SecurityContext `json:"securityContext"`
	Command         []string        `json:"command"`
	// VolumeMounts    []VolumeMount   `json:"volumeMounts"`
	Resources ResourcesSpec `json:"resources"`
}
type ResourcesSpec struct {
	Limits   ResourceLimits `json:"limits"`
	Requests ResourceReqs   `json:"requests"`
}

type ResourceLimits struct {
	// Hugepages2Mi string `json:"hugepages-2Mi"`
	// Hugepages1Gi string `json:"hugepages-1Gi"`
	CPU    string `json:"cpu"`
	Memory string `json:"memory"`
}

type ResourceReqs struct {
	CPU    string `json:"cpu"`
	Memory string `json:"memory"`
	// Hugepages2Mi string `json:"hugepages-2Mi"`
	// Hugepages1Gi string `json:"hugepages-1Gi"`
}

// type VolumeMount struct {
// 	MountPath string `json:"mountPath"`
// 	Name      string `json:"name"`
// }

// type VolumeSpec struct {
// 	Name     string `json:"name"`
// 	HostPath struct {
// 		Path string `json:"path"`
// 	} `json:"hostPath"`
// 	EmptyDir struct {
// 		Medium string `json:"medium"`
// 	} `json:"emptyDir"`
// }

type SecurityContext struct {
	// RunAsUser              *int64       `json:"runAsUser,omitempty"`
	Privileged *bool `json:"privileged,omitempty"`
	// RunAsNonRoot           *bool        `json:"runAsNonRoot,omitempty"`
	// ReadOnlyRootFilesystem *bool        `json:"readOnlyRootFilesystem,omitempty"`
	// Capabilities           Capabilities `json:"capabilities"`
}

//	type Capabilities struct {
//		Add []string `json:"add"`
//	}
type AcceleratorSelector struct {
	PciAddress string `json:"pciAddress"`
}

type PhysicalFunction struct {
	PFDriver string `json:"pfDriver"`
	VFDriver string `json:"vfDriver"`
	VFAmount int    `json:"vfAmount"`
}

// SriovT2CardStatus defines the observed state of SriovT2Card
type SriovT2CardStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// SriovT2Card is the Schema for the sriovt2cards API
type SriovT2Card struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SriovT2CardSpec   `json:"spec,omitempty"`
	Status SriovT2CardStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// SriovT2CardList contains a list of SriovT2Card
type SriovT2CardList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SriovT2Card `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SriovT2Card{}, &SriovT2CardList{})
}
