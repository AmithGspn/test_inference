# echo "------------------------------------------------------------"
# /home/admin/p4c/build/p4c-dpdk --arch pna main.p4 -o lab7.spec

export RTE_INSTALL_DIR=/home/admin/dpdk
export LAB_DIR=/home/admin/in-network-inference-using-p4/src/dpdk/

echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

$RTE_INSTALL_DIR/examples/pipeline/build/pipeline -c 0x3 --vdev=net_tap0,mac="00:00:00:00:00:01" --vdev=net_tap1,mac="00:00:00:00:00:02" --vdev=net_tap2,mac="00:00:00:00:00:03" --  -s $LAB_DIR/network_inference.cli
