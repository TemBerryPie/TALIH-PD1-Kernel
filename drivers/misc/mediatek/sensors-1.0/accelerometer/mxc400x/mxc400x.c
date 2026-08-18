/*
 * mxc400x accelerometer driver for tb8788p1_64_wifi (memsic MXC400X/MXC665X)
 *
 * Reconstructed from the stock kernel binary (mxc400x_i2c_probe,
 * MXC400X_SetPowerMode): CTRL reg 0x0D, 0x41 = active / 0x40 = standby,
 * chip id 0x02. Data = 12-bit 2's complement at 0x03..0x08.
 * The tablet DT (gsensor@18) provides mxc665x_addr (0x15) + direction,
 * read by the stock elink layer - the generic cust_acc helper would not
 * work because the node has no generic i2c_addr property.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/i2c.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/of.h>

#include <cust_acc.h>
#include <accel.h>
#include <sensors_io.h>
#include <sensor_list.h>
#include <hwmsensor.h>

#define MXC400X_DEV_NAME		"mxc400x"

#define MXC400X_REG_XOUT		0x03
#define MXC400X_REG_CTRL		0x0D
#define MXC400X_REG_WHO_AM_I		0x0E

#define MXC400X_CHIP_ID			0x02

#define MXC400X_CTRL_SHUTDOWN		0x00
#define MXC400X_CTRL_STANDBY		0x01
#define MXC400X_CTRL_ACTIVE		0x40

#define MXC400X_AXES_NUM		3
#define MXC400X_DATA_LEN		6

#define MXC400X_GRAVITY_EARTH_1000	9807

static DEFINE_MUTEX(mxc400x_mutex);

struct mxc400x_i2c_data {
	struct i2c_client *client;
	struct acc_hw *hw;
	struct hwmsen_convert cvt;
	atomic_t trace;
	atomic_t suspend;
	u8 enabled;
};

static struct i2c_client *mxc400x_i2c_client;

static int mxc400x_i2c_read_block(struct i2c_client *client, u8 addr,
				  u8 *data, u8 len)
{
	u8 beg = addr;
	struct i2c_msg msgs[2] = {
		{
			.addr = client->addr,
			.flags = 0,
			.len = 1,
			.buf = &beg,
		},
		{
			.addr = client->addr,
			.flags = I2C_M_RD,
			.len = len,
			.buf = data,
		},
	};
	int err;

	if (!client)
		return -EINVAL;

	err = i2c_transfer(client->adapter, msgs, sizeof(msgs) / sizeof(msgs[0]));
	if (err != 2) {
		pr_err("%s: i2c_transfer error: (%d %p %d) %d\n",
		       __func__, 0, data, len, err);
		return -1;
	}
	return 0;
}

static int mxc400x_i2c_write_block(struct i2c_client *client, u8 addr,
				   u8 *data, u8 len)
{
	u8 buf[8];
	int err;

	if (len > 7)
		return -EINVAL;
	buf[0] = addr;
	memcpy(&buf[1], data, len);
	err = i2c_master_send(client, buf, len + 1);
	if (err < 0) {
		pr_err("%s: send error: %d\n", __func__, err);
		return -1;
	}
	return 0;
}

static int mxc400x_read_chipid(struct i2c_client *client, u8 *id)
{
	int err;
	u8 buf;

	err = mxc400x_i2c_read_block(client, MXC400X_REG_WHO_AM_I, &buf, 1);
	if (err)
		return err;
	*id = buf;
	return 0;
}

static int mxc400x_set_power_mode(struct i2c_client *client, bool enable)
{
	u8 buf = enable ? MXC400X_CTRL_ACTIVE : MXC400X_CTRL_STANDBY;
	int err;

	err = mxc400x_i2c_write_block(client, MXC400X_REG_CTRL, &buf, 1);
	if (err)
		pr_err("%s: set power mode %d fail\n", __func__, enable);
	return err;
}

static int mxc400x_read_data(struct i2c_client *client, int *x, int *y, int *z)
{
	u8 buf[MXC400X_DATA_LEN];
	int err;

	/* tb8788p1 (MXC665X): X=0x03/0x04, Y=0x05/0x06, Z=0x07/0x08 -
	 * one 6-byte block read covers all three axes (12-bit left-aligned,
	 * big-endian per axis). The earlier 0x0A/0x0B "Z" was actually a
	 * fixed chip register (0x2b, never moves with tilt). */
	err = mxc400x_i2c_read_block(client, MXC400X_REG_XOUT, buf,
				     MXC400X_DATA_LEN);
	if (err)
		return err;

	*x = (int)((s16)((buf[0] << 8) | buf[1]) >> 4);
	*y = (int)((s16)((buf[2] << 8) | buf[3]) >> 4);
	*z = (int)((s16)((buf[4] << 8) | buf[5]) >> 4);
	return 0;
}

/* if use this macro the driver is exposed as the input device */
/* #define MXC400X_INPUT_DEVICE */

static int mxc400x_init_client(struct i2c_client *client)
{
	struct mxc400x_i2c_data *obj = i2c_get_clientdata(client);
	u8 chipid = 0;
	int err;

	err = mxc400x_read_chipid(client, &chipid);
	if (err)
		return err;
	/* the stock driver checks (id & 0x3E) == 0x02 (MXC400X_CheckDeviceID) */
	if ((chipid & 0x3E) != MXC400X_CHIP_ID) {
		pr_err("%s: chip id 0x%02x is not mxc400x!\n", __func__,
		       chipid);
		return -ENODEV;
	}
	pr_info("%s: mxc400x chip id 0x%02x ok\n", __func__, chipid);

	err = mxc400x_set_power_mode(client, false);
	if (err)
		return err;
	obj->enabled = 0;
	return 0;
}

static int mxc400x_open_report_data(int open)
{
	return 0;
}

static int mxc400x_enable_nodata(int en)
{
	int err = 0;

	mutex_lock(&mxc400x_mutex);
	if (!mxc400x_i2c_client) {
		mutex_unlock(&mxc400x_mutex);
		return -ENODEV;
	}
	err = mxc400x_set_power_mode(mxc400x_i2c_client, en ? true : false);
	mutex_unlock(&mxc400x_mutex);
	return err;
}

static int mxc400x_set_delay(u64 ns)
{
	/* MXC400X has a fixed internal ODR, nothing to program */
	return 0;
}

static int mxc400x_acc_batch(int flag, int64_t samplingPeriodNs,
			     int64_t maxBatchReportLatencyNs)
{
	return mxc400x_set_delay(samplingPeriodNs);
}

static int mxc400x_acc_flush(void)
{
	return acc_flush_report();
}

static int mxc400x_get_data(int *x, int *y, int *z, int *status)
{
	int err = 0;

	mutex_lock(&mxc400x_mutex);
	if (!mxc400x_i2c_client) {
		mutex_unlock(&mxc400x_mutex);
		return -ENODEV;
	}
	err = mxc400x_read_data(mxc400x_i2c_client, x, y, z);
	mutex_unlock(&mxc400x_mutex);
	if (!err) {
		/* tb8788p1: the chip runs in the +-8g range (256 counts/g,
		 * not 1024) - verified against the stock kernel's live
		 * values (stock 7.13/6.87 vs our 1.79/1.19 = exactly 4x) */
		*x = (*x * MXC400X_GRAVITY_EARTH_1000) / 256;
		*y = (*y * MXC400X_GRAVITY_EARTH_1000) / 256;
		*z = (*z * MXC400X_GRAVITY_EARTH_1000) / 256;
		*status = SENSOR_STATUS_ACCURACY_HIGH;
	} else {
		pr_err("%s: read data fail\n", __func__);
	}
	return err;
}

static const struct i2c_device_id mxc400x_i2c_id[] = {
	{MXC400X_DEV_NAME, 0},
	{}
};

#ifdef CONFIG_OF
static const struct of_device_id mxc400x_of_match[] = {
	{.compatible = "mediatek,gsensor",},
	{},
};
MODULE_DEVICE_TABLE(of, mxc400x_of_match);
#endif

static int mxc400x_i2c_probe(struct i2c_client *client,
			     const struct i2c_device_id *id)
{
	struct mxc400x_i2c_data *obj;
	struct acc_control_path ctl = {0};
	struct acc_data_path data = {0};
	struct sensorInfo_NonHub_t gsensor_devinfo;
	struct device_node *node = client->dev.of_node;
	u32 addr = 0x15, direction = 0;
	int err;

	memset(&gsensor_devinfo, 0, sizeof(gsensor_devinfo));

	pr_info("%s: mxc400x driver probe\n", __func__);

	if (node) {
		of_property_read_u32(node, "mxc665x_addr", &addr);
		of_property_read_u32(node, "mxc665x_direction", &direction);
	}
	pr_info("%s: mxc665x_addr from dts is 0x%x, direction %d\n",
		__func__, addr, direction);
	client->addr = (unsigned short)addr;

	obj = kzalloc(sizeof(*obj), GFP_KERNEL);
	if (!obj)
		return -ENOMEM;

	obj->client = client;
	obj->hw = kzalloc(sizeof(struct acc_hw), GFP_KERNEL);
	if (!obj->hw) {
		kfree(obj);
		return -ENOMEM;
	}
	obj->hw->direction = (int)direction;
	err = hwmsen_get_convert(obj->hw->direction, &obj->cvt);
	if (err) {
		pr_err("%s: invalid direction %d\n", __func__, direction);
		kfree(obj->hw);
		kfree(obj);
		return err;
	}
	atomic_set(&obj->trace, 0);
	atomic_set(&obj->suspend, 0);

	mxc400x_i2c_client = client;
	i2c_set_clientdata(client, obj);

	err = mxc400x_init_client(client);
	if (err)
		goto exit_kfree;

	ctl.open_report_data = mxc400x_open_report_data;
	ctl.enable_nodata = mxc400x_enable_nodata;
	ctl.set_delay = mxc400x_set_delay;
	ctl.is_report_input_direct = false;
	ctl.is_support_batch = false;
	ctl.batch = mxc400x_acc_batch;
	ctl.flush = mxc400x_acc_flush;
	err = acc_register_control_path(&ctl);
	if (err) {
		pr_err("%s: register acc control path err\n", __func__);
		goto exit_kfree;
	}

	data.get_data = mxc400x_get_data;
	data.vender_div = 1000;
	err = acc_register_data_path(&data);
	if (err) {
		pr_err("%s: register acc data path err\n", __func__);
		goto exit_kfree;
	}

	strncpy(gsensor_devinfo.name, MXC400X_DEV_NAME,
		sizeof(gsensor_devinfo.name));
	sensorlist_register_deviceinfo(ID_ACCELEROMETER, &gsensor_devinfo);

	pr_info("%s: OK\n", __func__);
	return 0;

exit_kfree:
	kfree(obj->hw);
	kfree(obj);
	mxc400x_i2c_client = NULL;
	return err;
}

static int mxc400x_i2c_remove(struct i2c_client *client)
{
	mxc400x_i2c_client = NULL;
	i2c_unregister_device(client);
	kfree(i2c_get_clientdata(client));
	return 0;
}

static struct i2c_driver mxc400x_i2c_driver = {
	.driver = {
		.name = MXC400X_DEV_NAME,
#ifdef CONFIG_OF
		.of_match_table = mxc400x_of_match,
#endif
	},
	.probe = mxc400x_i2c_probe,
	.remove = mxc400x_i2c_remove,
	.id_table = mxc400x_i2c_id,
};

static int mxc400x_local_init(void)
{
	if (i2c_add_driver(&mxc400x_i2c_driver)) {
		pr_err("%s: add driver error\n", __func__);
		return -1;
	}
	return 0;
}

static int mxc400x_local_uninit(void)
{
	i2c_del_driver(&mxc400x_i2c_driver);
	return 0;
}

static struct acc_init_info mxc400x_init_info = {
	.name = "mxc400x",
	.init = mxc400x_local_init,
	.uninit = mxc400x_local_uninit,
};

static int __init mxc400x_init(void)
{
	pr_info("%s: mxc400x driver version\n", __func__);
	acc_driver_add(&mxc400x_init_info);
	return 0;
}

static void __exit mxc400x_exit(void)
{
}

module_init(mxc400x_init);
module_exit(mxc400x_exit);

MODULE_DESCRIPTION("memsic mxc400x accelerometer driver");
MODULE_LICENSE("GPL v2");
