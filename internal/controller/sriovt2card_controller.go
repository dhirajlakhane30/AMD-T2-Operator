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

package controller

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	// "sync"

	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	sriovfect2v1 "github.com/AMDEPYC/AMD-T2/api/v1"
)

// SriovT2CardReconciler reconciles a SriovT2Card object
type SriovT2CardReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// Clientset *kubernetes.Clientset
	// Log       logr.Logger
}

var (
	setupLog    = log.Log.WithName("setup")
	pciAddress  string
	dockerImage string
	myNameSpace string
)

//+kubebuilder:rbac:groups=sriovfect2.amd.com,resources=sriovt2cards,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=sriovfect2.amd.com,resources=sriovt2cards/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=sriovfect2.amd.com,resources=sriovt2cards/finalizers,verbs=update
// +kubebuilder:rbac:groups=sriovfect2.amd.com,resources=daemonsets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=sriovfect2.amd.com,resources=serviceaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=apps,resources=daemonsets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=apps,resources=serviceaccounts,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the SriovT2Card object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.15.0/pkg/reconcile
func (r *SriovT2CardReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	setupLog := log.FromContext(ctx)

	cr := &sriovfect2v1.SriovT2Card{}
	if err := r.Get(ctx, req.NamespacedName, cr); err != nil {
		if k8serrors.IsNotFound(err) {
			// Clean up all resources when the CR is deleted
			setupLog.Info("Cleaning up all resources related to the SriovT2Card")
			if cleanupErr := r.cleanupResources(ctx, req.NamespacedName.Namespace); cleanupErr != nil {
				setupLog.Error(cleanupErr, "Failed to clean up resources")
				return ctrl.Result{}, cleanupErr
			}
			fmt.Println("ALL CleanUp Done...")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	setupLog.Info("Starting reconciliation process for SriovT2Card", "namespace", cr.Namespace)

	fmt.Println("x.........AMD-T2-Card...........x")

	myNameSpace = cr.Namespace
	dockerImage = cr.Spec.Template.Spec.Containers[0].Image

	pciAddress = cr.Spec.AcceleratorSelector.PciAddress

	nodeName := cr.Spec.NodeSelector["kubernetes.io/hostname"]
	fmt.Println("nodename: " + nodeName)

	fmt.Println("Basic Setup Started...")

	// err := createServiceAccounts(ctx, r.Client)
	// if err != nil {
	// 	setupLog.Error(err, "Failed to create ServiceAccount")
	// }
	// Create a DaemonSet to run the necessary commands on all nodes

	setupDaemonSet := generateSetupDaemonSet(cr, r.Client, pciAddress)

	if err := r.applyOrUpdateDaemonSet(ctx, setupDaemonSet); err != nil {
		setupLog.Error(err, "Failed to create, update, or delete Setup DaemonSet")
		return ctrl.Result{}, err
	}
	setupLog.Info("Setup DaemonSet processed successfully")

	time.Sleep(10 * time.Second)

	// driverLoadedCh := make(chan bool)

	// // Start the driver monitoring in a goroutine
	// go func() {
	// 	loaded := WaitForDriverLogInDaemonSet(ctx, r.Client, cr.Namespace)
	// 	driverLoadedCh <- loaded
	// }()

	// select {
	// case loaded := <-driverLoadedCh:
	// 	if loaded {
	// 		r.Log.Info("Driver loaded, continuing reconciliation")
	// 	} else {
	// 		r.Log.Error(errors.New("driver not loaded"), "Timeout or failure while waiting for driver")
	// 		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	// 	}

	// case <-time.After(2 * time.Minute):
	// 	r.Log.Error(errors.New("timeout"), "Timeout waiting for driver to load")
	// 	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	// }

	fmt.Println("Adding Resources To Node Level...")
	fmt.Println("Please ensure you have added the qdma-pf.ko file")

	time.Sleep(2 * time.Minute)

	dsPluginNew, _ := applySriovDevicePluginConfigNew(ctx, r.Client)

	// Check if the DaemonSet already exists
	existingDs := &appsv1.DaemonSet{}
	err1 := r.Client.Get(ctx, client.ObjectKey{Name: dsPluginNew.Name, Namespace: cr.Namespace}, existingDs)

	if err1 == nil {
		if err1 := r.Client.Delete(ctx, existingDs); err1 != nil {
			setupLog.Error(err1, "failed to delete existing DaemonSet")
		}
		fmt.Println("Existing DaemonSet deleted.")
	}

	time.Sleep(10 * time.Second)

	time.Sleep(1 * time.Minute)

	if err := r.Client.Create(ctx, dsPluginNew); err != nil {
		setupLog.Error(err, "Failed to apply SR-IOV device plugin configuration: DaemonSet creation failed")
		return ctrl.Result{}, err
	}
	setupLog.Info("SR-IOV device plugin DaemonSet created successfully")

	// } else if err == nil {
	// 	// DaemonSet already exists, updating it
	// 	dsPluginNew.ResourceVersion = existingDs.ResourceVersion // Keep the existing resource version
	// 	if err := r.Client.Update(ctx, dsPluginNew); err != nil {
	// 		setupLog.Error(err, "Failed to apply SR-IOV device plugin configuration: DaemonSet update failed")
	// 		return ctrl.Result{}, err
	// 	}
	// 	setupLog.Info("SR-IOV device plugin DaemonSet updated successfully")
	// } else {
	// 	setupLog.Error(err, "Failed to retrieve DaemonSet")
	// 	return ctrl.Result{}, err
	// }
	setupLog.Info("SR-IOV device plugin configuration applied successfully")
	time.Sleep(5 * time.Second)
	fmt.Println("Adding Resources To Node Level Completed...")
	time.Sleep(10 * time.Second)

	setupLog.Info("Reconciliation process completed successfully...")
	setupLog.Info("Start monitoring the devices and reapplying if needed...")

	// go monitorAndReapply(ctx, r.Client, cr.Namespace, nodeName)
	return ctrl.Result{}, nil
}

// applyOrUpdateDaemonSet handles DaemonSet creation, updates, and deletion after job completion
func (r *SriovT2CardReconciler) applyOrUpdateDaemonSet(ctx context.Context, ds *appsv1.DaemonSet) error {
	existingDS := &appsv1.DaemonSet{}
	err := r.Client.Get(ctx, client.ObjectKey{Name: ds.Name, Namespace: ds.Namespace}, existingDS)
	if err != nil && k8serrors.IsNotFound(err) {
		// DaemonSet does not exist, create it
		if createErr := r.Client.Create(ctx, ds); createErr != nil {
			return fmt.Errorf("failed to create DaemonSet: %w", createErr)
		}
		return nil
	} else if err != nil {
		// Error fetching DaemonSet
		return fmt.Errorf("failed to get DaemonSet: %w", err)
	}

	// Check if the DaemonSet has finished its job
	if existingDS.Status.NumberReady == existingDS.Status.DesiredNumberScheduled {
		// Delete the DaemonSet after completion
		if delErr := r.Client.Delete(ctx, existingDS); delErr != nil {
			return fmt.Errorf("failed to delete DaemonSet after job completion: %w", delErr)
		}
		setupLog := log.FromContext(ctx)
		setupLog.Info("Setup DaemonSet deleted after job completion", "name", ds.Name)
		return nil
	}

	// Update DaemonSet if the spec has changed
	if !equality.Semantic.DeepEqual(existingDS.Spec, ds.Spec) {
		existingDS.Spec = ds.Spec
		if updateErr := r.Client.Update(ctx, existingDS); updateErr != nil {
			return fmt.Errorf("failed to update DaemonSet: %w", updateErr)
		}
	}
	return nil
}

// Function to run the loop every 5 minutes
func monitorAndReapply(ctx context.Context, kubeClient client.Client, namespace string, nodeName string) {
	// resourcePF := "amd.com/amd_xilinx_t2_pf"
	resourceVF := "amd.com/amd-t2-resource"

	for {
		// pfAvailable, err := isResourceAvailable(ctx, kubeClient, nodeName, resourcePF)
		// if err != nil {
		// 	fmt.Printf("Error checking PF resource availability: %v\n", err)
		// }

		vfAvailable, err := isResourceAvailable(ctx, kubeClient, nodeName, resourceVF)
		if err != nil {
			fmt.Printf("Error checking VF resource availability: %v\n", err)
		}

		// if !pfAvailable || !vfAvailable {
		if !vfAvailable {
			setupLog.Info("VFs not allocated to node. Reapplying SR-IOV device plugin configuration...")

			fmt.Println("in the reapplying")
			existingDs := &appsv1.DaemonSet{}
			err := kubeClient.Get(ctx, client.ObjectKey{Name: "sriov-device-plugin", Namespace: "kube-system"}, existingDs)
			if err == nil {
				if err := kubeClient.Delete(ctx, existingDs); err != nil {
					fmt.Printf("Failed to delete existing DaemonSet: %v\n", err)
				} else {
					fmt.Println("Existing DaemonSet deleted during reapply.")
				}
			}

			time.Sleep(10 * time.Second)
			_, err1 := applySriovDevicePluginConfigNew(ctx, kubeClient)
			time.Sleep(2 * time.Second)
			if err1 != nil {
				fmt.Printf("Error applying SR-IOV device plugin configuration: %v\n", err1)
			} else {
				fmt.Println("SR-IOV device plugin configuration applied successfully")
			}
		} else {
			fmt.Println("Resources are available, no action needed")
		}

		time.Sleep(2 * time.Minute)
	}
}

func isResourceAvailable(ctx context.Context, kubeClient client.Client, nodeName string, resourceName string) (bool, error) {
	node := &corev1.Node{}
	err := kubeClient.Get(ctx, types.NamespacedName{Name: nodeName}, node)
	if err != nil {
		return false, fmt.Errorf("failed to get node %s: %v", nodeName, err)
	}

	allocatable, ok := node.Status.Allocatable[corev1.ResourceName(resourceName)]
	if !ok {
		return false, fmt.Errorf("resource %s not found on node %s", resourceName, nodeName)
	}

	fmt.Println("vfs values allocatable in resource avaialble func: ", allocatable.Value())

	if allocatable.Value() > 0 {
		return true, nil
	}

	return false, nil
}

// Cleanup function to remove all resources related to the operator
func (r *SriovT2CardReconciler) cleanupResources(ctx context.Context, namespace string) error {
	setupLog := log.FromContext(ctx)
	fmt.Println("Cleaning up resources Started...")

	daemonSetList_pre := &appsv1.DaemonSetList{}
	if err := r.Client.List(ctx, daemonSetList_pre, client.InNamespace(namespace)); err != nil {
		return err
	}

	for _, ds := range daemonSetList_pre.Items {
		if err := r.Client.Delete(ctx, &ds); err != nil {
			setupLog.Error(err, "Failed to delete DaemonSet", "DaemonSet", ds.Name)
			return err
		}
		setupLog.Info("Deleting DaemonSet", "DaemonSet", ds.Name)
	}

	time.Sleep(32 * time.Second)

	// Set VFs amount to 0
	cr := &sriovfect2v1.SriovT2Card{}
	if err := resetSriovVfs(ctx, r.Client, cr); err != nil {
		setupLog.Error(err, "Failed to reset SR-IOV VFs")
		return err
	}
	setupLog.Info("Successfully reset SR-IOV VFs to 0")
	time.Sleep(3 * time.Second)
	// Delete all DaemonSets created by the operator
	daemonSetList := &appsv1.DaemonSetList{}
	if err := r.Client.List(ctx, daemonSetList, client.InNamespace(namespace)); err != nil {
		return err
	}

	for _, ds := range daemonSetList.Items {
		if err := r.Client.Delete(ctx, &ds); err != nil {
			setupLog.Error(err, "Failed to delete DaemonSet", "DaemonSet", ds.Name)
			return err
		}
		setupLog.Info("Deleted DaemonSet", "DaemonSet", ds.Name)
	}

	setupLog.Info("Successfully cleaned up all resources")

	return nil
}

// Function to reset SR-IOV VFs to 0
func resetSriovVfs(ctx context.Context, client client.Client, cr *sriovfect2v1.SriovT2Card) error {
	fmt.Println("inside vfs function")

	// Generate the DaemonSet for resetting SR-IOV VFs
	resetDs := generateResetDaemonSet(cr)

	// Ensure that the DaemonSet is generated successfully
	if resetDs == nil {
		return fmt.Errorf("failed to generate reset DaemonSet due to missing parameters")
	}

	// Create the DaemonSet
	if err := client.Create(ctx, resetDs); err != nil {
		return fmt.Errorf("failed to create reset DaemonSet: %v", err)
	}

	// Wait for DaemonSet to complete its job (this may require a more robust check, not just sleep)
	time.Sleep(5 * time.Second)

	// Reset global variables (optional, if needed)
	pciAddress = ""
	dockerImage = ""
	myNameSpace = ""
	time.Sleep(5 * time.Second)

	// Delete the DaemonSet after the reset operation is complete
	if err := client.Delete(ctx, resetDs); err != nil {
		return fmt.Errorf("failed to delete reset DaemonSet: %v", err)
	}

	fmt.Println("Successfully reset SR-IOV VFs")
	return nil
}

// Function to generate the DaemonSet for resetting SR-IOV VFs with hard-coded values
func generateResetDaemonSet(cr *sriovfect2v1.SriovT2Card) *appsv1.DaemonSet {
	fmt.Println("Inside the Reset Vfs function")

	// pciAddress = cr.Spec.AcceleratorSelector.PciAddress
	// dockerImage = cr.Spec.Template.Spec.Containers[0].Image
	// myNameSpace = cr.Namespace
	fmt.Println("image: " + dockerImage)

	// Ensure pciAddress, dockerImage, and myNameSpace are not empty
	if pciAddress == "" || dockerImage == "" || myNameSpace == "" {
		fmt.Println("pciAddress, dockerImage, or myNameSpace is empty, cannot proceed")
		return nil
	}

	// Define hard-coded values
	pciDevicesPath := "/sys/bus/pci/devices/" + pciAddress
	systemNodePath := "/sys/devices/system/node"
	lib := "/lib/modules"
	headers := "/usr/src"
	// driverName := "vfio-pci"

	// Construct reset command
	// resetCmd := fmt.Sprintf(`echo 0 > /sys/bus/pci/devices/%s/sriov_numvfs`,
	// 	pciAddress)
	resetCmd := fmt.Sprintf(`echo 0 > /sys/bus/pci/devices/%s/sriov_numvfs && echo "VFs after reset:" && cat /sys/bus/pci/devices/%s/sriov_numvfs && echo "Running lspci to verify Xilinx devices:" && lspci | grep -i xili | wc -l`, pciAddress, pciAddress)

	fmt.Printf("Constructed resetCmd: %s\n", resetCmd)

	// Define the container
	container := corev1.Container{
		Name:  "reset-sriov-vfs",
		Image: dockerImage, // Make sure this is set
		Command: []string{
			"sh", "-c", resetCmd,
		},
		SecurityContext: &corev1.SecurityContext{
			Privileged: boolPtr(true),
		},
		Env: []corev1.EnvVar{
			{Name: "pci-devices", Value: pciDevicesPath},
			{Name: "system-node", Value: systemNodePath},
			{Name: "lib", Value: lib},
			{Name: "headers", Value: headers},
		},
		VolumeMounts: []corev1.VolumeMount{
			{Name: "lib", MountPath: "/lib/modules"},
			{Name: "headers", MountPath: "/usr/src"},
		},
	}

	// Define the DaemonSet
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "reset-sriov-vfs",
			Namespace: myNameSpace, // Ensure this is set
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app":  "dpdk",
					"card": "SriovT2Card",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app":  "dpdk",
						"card": "SriovT2Card",
					},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: "amd-t2-january-controller-manager",
					Containers:         []corev1.Container{container},
					// ImagePullSecrets: []corev1.LocalObjectReference{
					// 	{Name: "t2-operator-quay-secret"},
					// },
					Volumes: []corev1.Volume{
						{
							Name: "pci-devices",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: pciDevicesPath,
								},
							},
						},
						{
							Name: "system-node",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: systemNodePath,
								},
							},
						},
						{
							Name: "lib",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/lib/modules",
								},
							},
						},
						{
							Name: "headers",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/usr/src",
								},
							},
						},
					},
				},
			},
		},
	}
	fmt.Println("Generated DaemonSet for resetting VFs")
	return ds
}

// Function to execute a command inside a pod and return the output
func execCommand(ctx context.Context, client interface{}, command string) (string, error) {
	fmt.Println("Inside The execCommand")
	fmt.Println("cmd: ", command)

	// cmd := exec.Command("sh", "-c", command)
	cmd := exec.Command(command)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("error executing command: %v", err)
	}

	// Trim any leading or trailing spaces from the output
	outputString := strings.TrimSpace(string(output))
	fmt.Println("Output of command:", outputString)
	return outputString, nil
}

// func WaitForDriverLogInDaemonSet(ctx context.Context, k8sClient client.Client, namespace string) bool {
// 	timeout := time.After(90 * time.Second)
// 	ticker := time.NewTicker(5 * time.Second)
// 	defer ticker.Stop()

// 	for {
// 		select {
// 		case <-timeout:
// 			return false
// 		case <-ticker.C:
// 			pods := &corev1.PodList{}
// 			if err := k8sClient.List(ctx, pods, client.InNamespace(namespace), client.MatchingLabels{"app": "driver-loader"}); err != nil {
// 				continue
// 			}

// 			for _, pod := range pods.Items {
// 				if strings.Contains(pod.Name, "driver-loader") {
// 					logs, err := getPodLogs(ctx, k8sClient, pod)
// 					if err == nil && strings.Contains(logs, "Driver loaded successfully") {
// 						return true
// 					}
// 				}
// 			}
// 		}
// 	}
// }

// func getPodLogs(ctx context.Context, k8sClient client.Client, pod corev1.Pod) (string, error) {
// 	// Use in-cluster config
// 	cfg, err := rest.InClusterConfig()
// 	if err != nil {
// 		return "", err
// 	}

// 	clientset, err := kubernetes.NewForConfig(cfg)
// 	if err != nil {
// 		return "", err
// 	}

// 	podLogOpts := corev1.PodLogOptions{
// 		Container: pod.Spec.Containers[0].Name,
// 	}

// 	req := clientset.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &podLogOpts)

// 	podLogs, err := req.Stream(ctx)
// 	if err != nil {
// 		return "", err
// 	}
// 	defer podLogs.Close()

// 	buf := new(bytes.Buffer)
// 	_, err = io.Copy(buf, podLogs)
// 	if err != nil {
// 		return "", err
// 	}

// 	return buf.String(), nil
// }

func generateSetupDaemonSet(cr *sriovfect2v1.SriovT2Card, c client.Client, pfAddresses string) *appsv1.DaemonSet {

	fmt.Println("Setup Daemonset called")
	pciDevicesPath := "/sys/bus/pci/devices/" + pfAddresses
	systemNodePath := "/sys/devices/system/node"
	lib := "/lib/modules"
	headers := "/usr/src"

	VfdriverName := cr.Spec.PhysicalFunction.VFDriver
	vfAmount := cr.Spec.PhysicalFunction.VFAmount
	pciAddress := cr.Spec.AcceleratorSelector.PciAddress

	setupLog.Info("Driver name", "driverName", VfdriverName)
	setupLog.Info("VF amount", "vfAmount", vfAmount)
	setupLog.Info("PCI address", "pciAddress", pciAddress)
	/*
		dynamicCmd := fmt.Sprintf(`
			   	        #!/bin/sh

			   echo "Starting qdma-pf module watchdog..."

			   # Wait until qdma-pf.ko becomes available
			   while [ ! -f /home/nonroot/coreos-qdma/qdma-pf.ko ]; do
			       echo "[WATCHDOG] qdma-pf.ko not found, retrying in 5s..."
			       sleep 5
			   done

			   echo "[WATCHDOG] qdma-pf.ko found. Starting module management loop..."

			   while true; do
			       # Check if the module is loaded
			       if lsmod | grep -q qdma; then
			           echo "[WATCHDOG] qdma module already loaded."
			       else
			           echo "[WATCHDOG] qdma module not loaded. Trying to insert..."
			           insmod /home/nonroot/coreos-qdma/qdma-pf.ko
			           if [ $? -eq 0 ]; then
			               echo "[WATCHDOG] qdma-pf.ko inserted successfully."
			           else
			               echo "[WATCHDOG] Failed to insert qdma-pf.ko"
			           fi
			       fi

			       # Perform DPDK setup if module is loaded
			       if lsmod | grep -q qdma; then
			           echo "[WATCHDOG] Running DPDK setup steps..."
			           modprobe %s
			           cd /home/nonroot/dpdk-stable
			           ./usertools/dpdk-devbind.py -b qdma-pf %s
			           echo 1 | tee /sys/module/vfio_pci/parameters/enable_sriov
			           echo %d | tee /sys/bus/pci/devices/%s/sriov_numvfs
			           for vf_path in /sys/bus/pci/devices/%s/virtfn*; do
			               if [ -e "$vf_path" ]; then
			                   vf_pci_address=$(basename $(readlink $vf_path))
			                   echo "[WATCHDOG] Binding VF: $vf_pci_address"
			                   ./usertools/dpdk-devbind.py -b vfio-pci $vf_pci_address
			               else
			                   echo "[WATCHDOG] VF path $vf_path does not exist. Skipping."
			               fi
			           done
			       fi

			       echo "[WATCHDOG] Sleeping 10s before next check..."
			       sleep 10
			   done
			   `, VfdriverName, pciAddress, vfAmount, pciAddress, pciAddress)
	*/

	dynamicCmd := fmt.Sprintf(`
						#!/bin/sh

						echo "Starting qdma-pf module watchdog..."

						while true; do
						    echo "[WATCHDOG] Checking for qdma-pf.ko..."

						    # Wait for the ko file if it doesn't exist
						    while [ ! -f /home/nonroot/coreos-qdma/qdma-pf.ko ]; do
						        echo "[WATCHDOG] qdma-pf.ko not found, retrying in 5s..."
						        sleep 5
						    done

						    # Check if the module is loaded
						    if lsmod | grep -q qdma; then
						        echo "[WATCHDOG] qdma module already loaded."
						    else
						        echo "[WATCHDOG] qdma module not loaded. Trying to insert..."
						        insmod /home/nonroot/coreos-qdma/qdma-pf.ko
						        if [ $? -eq 0 ]; then
						            echo "[WATCHDOG] qdma-pf.ko inserted successfully."
						        else
						            echo "[WATCHDOG] Failed to insert qdma-pf.ko"
						        fi
						    fi

						    # Perform one-time binding and setup (only if module is now loaded)
						    if lsmod | grep -q qdma; then
						        echo "[WATCHDOG] Running DPDK setup steps..."
								xilinx_count=$(lspci | grep -i xili | wc -l)
								total_vfs=$((xilinx_count - 1))
                                echo "total_vfs_available = $total_vfs"
								
								if [ "$xilinx_count" -lt 2 ]; then
								    echo "[WATCHDOG] Found $xilinx_count Xilinx devices. Running DPDK setup steps..."
						            modprobe %s
						            cd /home/nonroot/dpdk-stable
						            ./usertools/dpdk-devbind.py -b qdma-pf %s
						            echo 1 | tee /sys/module/vfio_pci/parameters/enable_sriov
						            echo %d | tee /sys/bus/pci/devices/%s/sriov_numvfs
						            for vf_path in /sys/bus/pci/devices/%s/virtfn*; do
						                if [ -e "$vf_path" ]; then
						                    vf_pci_address=$(basename $(readlink $vf_path))
						                    echo "[WATCHDOG] Binding VF: $vf_pci_address"
						                    ./usertools/dpdk-devbind.py -b vfio-pci $vf_pci_address
						                else
						                    echo "[WATCHDOG] VF path $vf_path does not exist. Skipping."
						                fi
						            done
								else
								    echo "[WATCHDOG]  Xilinx devices(VFs) found. Skipping VF setup."
						        fi
							fi
						    echo "[WATCHDOG] Sleeping 10s before next check..."
						    sleep 10
						done

						`, VfdriverName, pciAddress, vfAmount, pciAddress, pciAddress)

	/*
		dynamicCmd := fmt.Sprintf(`
			      #!/bin/sh

			      echo "Waiting for qdma-pf.ko to be available..."

			      # Wait until the .ko file appears
			      while [ ! -f /home/nonroot/coreos-qdma/qdma-pf.ko ]; do
			           echo "qdma-pf.ko not found yet, sleeping for 5 seconds..."
			           sleep 5
			      done

			      echo "qdma-pf.ko found. Checking if qdma module is already loaded..."

			      if lsmod | grep -q qdma; then
			         echo "qdma module already loaded, skipping insmod."
			      else
			         echo "qdma module not loaded. Attempting to insert module..."
			         insmod /home/nonroot/coreos-qdma/qdma-pf.ko
			         if [ $? -eq 0 ]; then
			             echo "qdma-pf.ko inserted successfully."
			         else
			             echo "Failed to insert qdma-pf.ko"
			             exit 1
			         fi
			      fi

			      # Continue with the rest of your logic
			      modprobe %s &&
			      cd /home/nonroot/dpdk-stable &&
			      ./usertools/dpdk-devbind.py -b qdma-pf %s &&
			      echo 1 | tee /sys/module/vfio_pci/parameters/enable_sriov &&
			      echo %d | tee /sys/bus/pci/devices/%s/sriov_numvfs &&
			      for vf_path in /sys/bus/pci/devices/%s/virtfn*; do
			          if [ -e "$vf_path" ]; then
			              vf_pci_address=$(basename $(readlink $vf_path))
			              echo "Binding VF: $vf_pci_address"
			             ./usertools/dpdk-devbind.py -b vfio-pci $vf_pci_address
			          else
			             echo "VF path $vf_path does not exist. Skipping."
			          fi
			      done

			      sleep infinity`, VfdriverName, pciAddress, vfAmount, pciAddress, pciAddress)
	*/
	/*
		dynamicCmd := fmt.Sprintf(`
					    modprobe %s &&
						cd /home/nonroot/dpdk-stable &&
					    ./usertools/dpdk-devbind.py -b qdma-pf %s &&
					    echo 1 | tee /sys/module/vfio_pci/parameters/enable_sriov &&
					    echo %d | tee /sys/bus/pci/devices/%s/sriov_numvfs &&
						for vf_path in /sys/bus/pci/devices/%s/virtfn*; do
					        if [ -e "$vf_path" ]; then
					           # Resolve the actual PCI address of the VF
					           vf_pci_address=$(basename $(readlink $vf_path))
					           echo "Binding VF: $vf_pci_address"
					           ./usertools/dpdk-devbind.py -b vfio-pci $vf_pci_address
					        else
					            echo "Error: VF path $vf_path does not exist. Skipping."
					        fi
					    done
						sleep infinity
					     `, VfdriverName, pciAddress, vfAmount, pciAddress, pciAddress)
	*/
	/*
			dynamicCmd := fmt.Sprintf(`
		    modprobe %s &&
			cd dpdk-stable &&
		    ./usertools/dpdk-devbind.py -b qdma-pf %s &&
		    echo 1 | tee /sys/module/vfio_pci/parameters/enable_sriov &&
		    echo %d > /sys/bus/pci/devices/%s/sriov_numvfs &&
		    for vf_path in /sys/bus/pci/devices/%s/virtfn*; do
		        vf_pci_address=$(basename $(readlink $vf_path))
		        ./usertools/dpdk-devbind.py -b vfio-pci $vf_pci_address
		    done &&
		     `, VfdriverName, pciAddress, vfAmount, pciAddress, pciAddress)

	*/
	container := cr.Spec.Template.Spec.Containers[0]

	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Name + "-setup",
			Namespace: cr.Namespace,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app":  "dpdk",
					"card": "SriovT2Card",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app":  "dpdk",
						"card": "SriovT2Card",
					},
				},
				Spec: corev1.PodSpec{

					ServiceAccountName: "amd-t2-january-controller-manager",
					Containers: []corev1.Container{
						{
							Name:  "setup-container",
							Image: container.Image,
							Command: []string{
								"sh", "-c", dynamicCmd,
							},
							// SecurityContext: &corev1.SecurityContext{
							// 	Privileged: boolPtr(true),
							// },
							SecurityContext: &corev1.SecurityContext{
								Privileged: boolPtr(true),
								Capabilities: &corev1.Capabilities{
									Add: []corev1.Capability{
										"SYS_ADMIN", "NET_ADMIN", "SYS_MODULE",
									},
								},
								RunAsUser: int64Ptr(0),
							},
							Env: []corev1.EnvVar{
								{
									Name:  "pci-devices",
									Value: pciDevicesPath,
								},
								{
									Name:  "system-node",
									Value: systemNodePath,
								},
								{
									Name:  "lib",
									Value: lib,
								},
								{
									Name:  "headers",
									Value: headers,
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "lib",
									MountPath: "/lib/modules",
								},
								{
									Name:      "headers",
									MountPath: "/usr/src",
								},
							},
							Resources: corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									corev1.ResourceName("hugepages-2Mi"): resource.MustParse("512Mi"),
									corev1.ResourceName("hugepages-1Gi"): resource.MustParse("1Gi"),
									corev1.ResourceCPU:                   resource.MustParse(container.Resources.Limits.CPU),
									corev1.ResourceMemory:                resource.MustParse(container.Resources.Limits.Memory),
								},
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse(container.Resources.Requests.CPU),
									corev1.ResourceMemory: resource.MustParse(container.Resources.Requests.Memory),
								},
							},
						},
					},
					// ImagePullSecrets: []corev1.LocalObjectReference{
					// 	{
					// 		Name: "t2-operator-quay-secret",
					// 	},
					// },
					Volumes: []corev1.Volume{
						{
							Name: "pci-devices",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: pciDevicesPath,
								},
							},
						},
						{
							Name: "system-node",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: systemNodePath,
								},
							},
						},
						{
							Name: "lib",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/lib/modules",
								},
							},
						},
						{
							Name: "headers",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/usr/src",
								},
							},
						},
					},
				},
			},
		},
	}
	return ds
}

func createServiceAccounts(ctx context.Context, c client.Client) error {
	// Define the service accounts
	serviceAccounts := []*corev1.ServiceAccount{
		// {
		// 	ObjectMeta: metav1.ObjectMeta{
		// 		Name:      "sriov-device-plugin",
		// 		Namespace: "kube-system",
		// 	},
		// },
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "amd-t2-january-controller-manager",
				Namespace: "amd-t2",
			},
		},
	}

	// Iterate and create each ServiceAccount
	for _, sa := range serviceAccounts {
		existingServiceAccount := &corev1.ServiceAccount{}
		err := c.Get(ctx, client.ObjectKey{Name: sa.Name, Namespace: sa.Namespace}, existingServiceAccount)
		if err == nil {
			fmt.Printf("ServiceAccount '%s' in namespace '%s' already exists.\n", sa.Name, sa.Namespace)
			continue
		}

		if err := c.Create(ctx, sa); err != nil {
			return fmt.Errorf("failed to create ServiceAccount '%s' in namespace '%s': %w", sa.Name, sa.Namespace, err)
		}
		fmt.Printf("ServiceAccount '%s' created successfully in namespace '%s'.\n", sa.Name, sa.Namespace)
	}
	return nil
}
func applySriovDevicePluginConfigNew(ctx context.Context, c client.Client) (*appsv1.DaemonSet, error) {
	fmt.Println("Applying SR-IOV Device Plugin Configuration...")
	// namespace := "kube-system"
	namespace := "amd-t2"

	// Create or update ConfigMap for SR-IOV device plugin
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sriovdp-config",
			Namespace: namespace,
		},
		Data: map[string]string{
			"config.json": `{
                "resourceList": [
                    {
                        "resourceName": "amd-t2-resource",
                        "resourcePrefix": "amd.com",
                        "deviceType": "accelerator",
                        "selectors": {
                            "vendors": ["10ee"],
                            "devices": ["a048"],
                            "drivers": ["vfio-pci"]
                        }
                    }
                ]
            }`,
		},
	}

	existingConfigMap := &corev1.ConfigMap{}
	err := c.Get(ctx, client.ObjectKey{Name: configMap.Name, Namespace: namespace}, existingConfigMap)
	if err == nil {
		// ConfigMap exists, delete it before reapplying
		if err := c.Delete(ctx, existingConfigMap); err != nil {
			return nil, fmt.Errorf("failed to delete existing ConfigMap: %v", err)
		}
		fmt.Println("Existing ConfigMap deleted.")
	}
	// Create the new ConfigMap
	if err := c.Create(ctx, configMap); err != nil {
		return nil, fmt.Errorf("failed to create ConfigMap: %v", err)
	}

	fmt.Println("ConfigMap created successfully.")

	// Create DaemonSet for SR-IOV device plugin
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sriov-device-plugin",
			Namespace: namespace,
			Labels: map[string]string{
				"tier": "node",
				"app":  "sriovdp",
			},
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"name": "sriov-device-plugin",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"name": "sriov-device-plugin",
						"tier": "node",
						"app":  "sriovdp",
					},
				},
				Spec: corev1.PodSpec{
					HostNetwork: true,
					HostPID:     true,
					NodeSelector: map[string]string{
						"beta.kubernetes.io/arch": "amd64",
					},
					Tolerations: []corev1.Toleration{
						{
							Key:      "node-role.kubernetes.io/master",
							Operator: corev1.TolerationOpExists,
							Effect:   corev1.TaintEffectNoSchedule,
						},
					},
					// ServiceAccountName: "sriov-device-plugin",
					ServiceAccountName: "amd-t2-january-controller-manager",
					Containers: []corev1.Container{
						{
							Name: "kube-sriovdp",
							// Image: "quay.io/amdaecgt2/amd-t2-device-plugin-ocp:v1.0.10",
							// Image: "quay.io/amdaecgt2/device-plugin:v1",
							Image: "quay.io/amdt2operator/device-plugin:v1.0.3",
							//Image:           "ghcr.io/k8snetworkplumbingwg/sriov-network-device-plugin:latest",
							ImagePullPolicy: corev1.PullIfNotPresent,
							Args: []string{
								"--log-dir=sriovdp",
								"--log-level=10",
							},
							SecurityContext: &corev1.SecurityContext{
								Privileged: boolPtr(true),
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "devicesock",
									MountPath: "/var/lib/kubelet/",
								},
								{
									Name:      "log",
									MountPath: "/var/log",
								},
								{
									Name:      "config-volume",
									MountPath: "/etc/pcidp/",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "devicesock",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/var/lib/kubelet/",
								},
							},
						},
						{
							Name: "log",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/var/log",
								},
							},
						},
						{
							Name: "config-volume",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "sriovdp-config",
									},
									Items: []corev1.KeyToPath{
										{
											Key:  "config.json",
											Path: "config.json",
										},
									},
								},
							},
						},
					},
					// Add the ImagePullSecrets here
					// ImagePullSecrets: []corev1.LocalObjectReference{
					// 	{
					// 		Name: "amdaecgt2-secret-amdt2",
					// 	},
					// },
				},
			},
		},
	}

	return ds, nil
}

func boolPtr(b bool) *bool {
	return &b
}

// Helper function to create a pointer to an int64 value
func int64Ptr(i int64) *int64 {
	return &i
}

// SetupWithManager sets up the controller with the Manager.
func (r *SriovT2CardReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sriovfect2v1.SriovT2Card{}).
		Complete(r)
}
