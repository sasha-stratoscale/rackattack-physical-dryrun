ROOTFS = build/root
YUMCACHE:=http://localhost:1012/yumcache.strato:1012

ifeq ($(V),1)
  Q =
else
  Q = @
endif

all: $(ROOTFS) check_convention

check_convention:
	pep8 py --max-line-length=150

submit:
	sudo -E solvent submitproduct rootfs $(ROOTFS)

unsubmit:
	sudo -E solvent unsubmit

approve:
	sudo -E solvent approve --product=rootfs

clean:
	@sudo rm -fr build
	@find -name "*.pyc" -delete
	

$(ROOTFS): build/smartctl
	-sudo mv $(ROOTFS) $(ROOTFS).tmp
	echo "Bringing source"
	-mkdir $(@D)
	sudo -E solvent bring --repositoryBasename=rootfs-basic --product=rootfs --destination=$(ROOTFS).tmp
	sudo chroot $(ROOTFS).tmp yum install $(RPMS_TO_INSTALL) --assumeyes
	sudo mkdir $(ROOTFS).tmp/usr/share/inaugurator
	sudo cp ../inaugurator/build/inaugurator.thin.initrd.img ../inaugurator/build/inaugurator.vmlinuz $(ROOTFS).tmp/usr/share/inaugurator
	sudo chmod 644 /usr/share/inaugurator/*
	sudo cp ../inaugurator/dist/inaugurator-1.0-py2.7.egg $(ROOTFS).tmp/tmp
	sudo chroot $(ROOTFS).tmp easy_install /tmp/inaugurator-1.0-py2.7.egg
	sudo chroot $(ROOTFS).tmp yum install --assumeyes $(YUMCACHE)/mirrors.kernel.org/fedora-epel/7/x86_64/m/msr-tools-1.3-1.el7.x86_64.rpm
	sudo chroot $(ROOTFS).tmp yum install --assumeyes $(YUMCACHE)/mirrors.kernel.org/fedora-epel/7/x86_64/v/vconfig-1.9-16.el7.x86_64.rpm
	sudo chroot $(ROOTFS).tmp yum install --assumeyes $(YUMCACHE)/mirrors.kernel.org/fedora-epel/7/x86_64/p/pigz-2.3.1-1.el7.x86_64.rpm
	sudo chroot $(ROOTFS).tmp pip install rpdb
	sudo chroot $(ROOTFS).tmp pip install ipaddr
	sudo sh -c "echo 'MaxSessions 300' >> $(ROOTFS).tmp/etc/ssh/sshd_config"
	sudo sh -c "echo 'UseDNS no' >> $(ROOTFS).tmp/etc/ssh/sshd_config"
	sudo cp $< $(ROOTFS).tmp/usr/sbin/
	sudo rm -fr $(ROOTFS).tmp/tmp/*
	sudo mv $(ROOTFS).tmp $(ROOTFS)

build/smartctl:
	-mkdir build
	cd build; wget $(YUMCACHE)/sourceforge.net/projects/smartmontools/files/smartmontools/6.3/smartmontools-6.3.tar.gz
	cd build; tar -xf smartmontools-6.3.tar.gz
	cd build/smartmontools-6.3; ./configure
	cd build/smartmontools-6.3; make
	cp build/smartmontools-6.3/smartctl $@

#requires: RACK_YAML
#requires: NODE_TO_DRY_RUN
dryrun:
	DISTRATO_INPUT_DIR=$(DISTRATO_INPUT_DIR) UPSETO_JOIN_PYTHON_NAMESPACES=yes PYTHONPATH=$(PWD):$(PWD)/py python py/rackattack/dryrun/main.py $(ARGS)
physdryrun:
	RACKATTACK_PROVIDER=tcp://rackattack-provider:1014@tcp://rackattack-provider:1015@http://rackattack-provider:1016 $(MAKE) dryrun

RPMS_TO_INSTALL = \
	dnsmasq \
	syslinux \
	ipmitool \
	strace \
	zip \
	tcpdump \
	unzip \
	pciutils \
	nmap-ncat

