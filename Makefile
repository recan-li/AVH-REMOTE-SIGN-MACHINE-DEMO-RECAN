
MQTT_DEMO_PATH      := AVH-CM7
USER_CONFIG_PATH    := config
OUT_PATH            := out
AVH_SIMLIMIT_TIME   := 8000000
SHELL 				:= /bin/bash
V  					?= 0

all: source clean build run

help:
	@echo "make help 	-> Show this help msg."
	@echo "make source 	-> Install env parameters."
	@echo "make build 	-> Build thie demo."
	@echo "make clean 	-> Clean object files."
	@echo "make run 	-> Run this demo."
	@echo "make debug 	-> Build & run this demo."
	@echo "make all 	-> Source & clean & build & run all together."
	@echo "make pip 	-> Install python tools by pip."

debug: build run

source:
	@echo "Copy and source .bashrc ..."
	@cp -rf .bashrc ~/.bashrc
	@. ~/.bashrc
	@echo "Copy CMSIS-Build-Utils.cmake ..."
	@sudo cp -rf cmake/CMSIS-Build-Utils.cmake /opt/ctools/etc/CMSIS-Build-Utils.cmake
	@echo "Install env parameters ..."
	cd $(MQTT_DEMO_PATH)/amazon-freertos/demos/include; \
	export MQTT_BROKER_TCP_PORT=1183;\
	envsubst <aws_clientcredential.h.in >aws_clientcredential.h; \
	envsubst <aws_clientcredential_keys.h.in >aws_clientcredential_keys.h
	@echo "All parameters have been installed."

build:
	@echo "Building ..."
	@test -e $(OUT_PATH) || mkdir -p $(OUT_PATH)
	/opt/ctools/bin/cbuild --packs $(MQTT_DEMO_PATH)/VHT_MPS2_Cortex-M7.cprj -v=$(V)
	@if [[ -e $(MQTT_DEMO_PATH)/Objects/image.elf ]]; then\
		cp -rf $(MQTT_DEMO_PATH)/Objects/image.elf $(MQTT_DEMO_PATH)/Objects/image.axf;\
	fi
	@cp -rf $(MQTT_DEMO_PATH)/Objects/image.axf $(OUT_PATH)

run:
	@echo "Running ..."
	/opt/VHT/bin/FVP_MPS2_Cortex-M7 --stat --simlimit $(AVH_SIMLIMIT_TIME) -f $(MQTT_DEMO_PATH)/vht_config.txt $(OUT_PATH)/image.axf

clean:
	@echo "Clean ..."
	rm -rf $(MQTT_DEMO_PATH)/Objects/
	rm -rf $(OUT_PATH)
	rm -rf aws_mqtt*.zip

pip:
	pip install -r $(MQTT_DEMO_PATH)/requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

.PHONY: all source clean build run help debug pip
