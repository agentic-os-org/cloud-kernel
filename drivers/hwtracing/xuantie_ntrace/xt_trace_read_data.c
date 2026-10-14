// SPDX-License-Identifier: GPL-2.0-only

#include <linux/kernel.h>
#include <linux/memory.h>
#include "xt_ntrace_control_interface.h"

/**
 * \brief        Get trRamWPLow vs High and Trace Data Size in the Sink
 * \param[in]    sink_info
 * \param[in]    config_info
 * \param[out]   write_point, the value of trRamWPLow vs High
 * \param[out]   size, the size of the trace data in the sink
 * \return       return -1 if access trace registers failed, otherwise return 0
 */
TRACE_CONTROL_LIB_API int32_t xt_trace_ram_sink_get_data_size(
	struct xt_trace_sink_control_info *sink_info, uint64_t *write_point)
{
	uint32_t tr_ram_wp_low = 0;
	uint32_t tr_ram_wp_high = 0;

	if (xt_trace_register_read(sink_info->base_addr + OFFSET_TRRAMWPLOW,
				   &tr_ram_wp_low))
		return -1;
	if (xt_trace_register_read(sink_info->base_addr + OFFSET_TRRAMWPHIGH,
				   &tr_ram_wp_high))
		return -1;

	*write_point = (((uint64_t)tr_ram_wp_high) << 32) + tr_ram_wp_low;

	//if (tr_ram_wp_low & 0x1)
	//	*size = config_info->ram_sink_limit - config_info->ram_sink_start;
	//else
	//	*size = *write_point - config_info->ram_sink_start;

	return 0;
}

TRACE_CONTROL_LIB_API int32_t xt_trace_read_data_from_sram_sink(
	uint64_t base_addr, uint64_t trace_data_start_address,
	uint64_t buffer_size, uint8_t *buffer)
{
	uint32_t tr_ram_data = 0;
	uint64_t read_length = 0;
	uint64_t tail_size = 0;
	bool need_write_address = true;

	/* Read unalign.  */
	if (trace_data_start_address & 0x3) {
		if (buffer_size > (4 - (trace_data_start_address & 0x3)))
			read_length = 4 - (trace_data_start_address & 0x3);
		else
			read_length = buffer_size;

		if (xt_trace_register_write(
			    base_addr + OFFSET_TRRAMRPHIGH,
			    (uint32_t)(trace_data_start_address >> 32)))
			return -1;
		if (xt_trace_register_write(
			    base_addr + OFFSET_TRRAMRPLOW,
			    ((uint32_t)trace_data_start_address & 0xfffffffc)))
			return -1;
		if (xt_trace_register_read(base_addr + OFFSET_TRRAMDATA,
					   &tr_ram_data))
			return -1;
		memcpy(buffer,
		       (uint8_t *)&tr_ram_data +
			       ((uint32_t)trace_data_start_address & 0x3),
		       read_length);
	}

	buffer += read_length;
	trace_data_start_address += read_length;
	read_length = buffer_size - read_length;
	tail_size = read_length & 0x3;
	read_length = read_length & ~0x3;

	if (read_length >= 4) {
		while (read_length > 0) {
			if (need_write_address) {
				if (xt_trace_register_write(
					    base_addr + OFFSET_TRRAMRPHIGH,
					    (uint32_t)(
						    trace_data_start_address >>
						    32)))
					return -1;
				if (xt_trace_register_write(
					    base_addr + OFFSET_TRRAMRPLOW,
					    ((uint32_t)trace_data_start_address &
					     0xfffffffc)))
					return -1;
				need_write_address = false;
			}

			if (xt_trace_register_read(base_addr + OFFSET_TRRAMDATA,
						   (uint32_t *)buffer))
				return -1;
			buffer += 4;
			trace_data_start_address += 4;
			read_length -= 4;
		}
	}

	if (tail_size) {
		if (xt_trace_register_write(
			    base_addr + OFFSET_TRRAMRPHIGH,
			    (uint32_t)(trace_data_start_address >> 32)))
			return -1;
		if (xt_trace_register_write(
			    base_addr + OFFSET_TRRAMRPLOW,
			    ((uint32_t)trace_data_start_address & 0xfffffffc)))
			return -1;
		if (xt_trace_register_read(base_addr + OFFSET_TRRAMDATA,
					   &tr_ram_data))
			return -1;
		memcpy(buffer, &tr_ram_data, tail_size);
	}

	return 0;
}

int32_t xt_trace_read_data_from_smem_sink(uint64_t base_addr,
					  uint64_t trace_data_start_address,
					  uint64_t buffer_size, uint8_t *buffer)
{
	if (xt_trace_memory_read(trace_data_start_address, buffer,
				 (uint32_t)buffer_size))
		return -1;

	return 0;
}

/**
 * \brief        Get trRamWPLow vs High and Trace Data Size in the Sink
 * \param[in]    sink_info
 * \param[in]    config_info
 * \param[in]    write_point, the value of trRamWPLow vs High
 * \param[in]    offset, the size of the trace data has been read
 * \param[in]    buffer_size, how many trace data needs to read
 * \param[in]    buffer, to save the trace data
 * \return       return -1 if access trace registers failed,
 * return 1, parameter error,
 * otherwise return 0
 */
/*
 *  For sink which is working on stop on wrap mode or trRamWPLow.trRamWrap == 0
 *  means that the start address of  the trace data is trRamStartLow/High. Otherwise
 *  the start address will be trRamWPLow/High.
 */
TRACE_CONTROL_LIB_API int32_t xt_trace_ram_sink_get_data(
	struct xt_trace_sink_control_info *sink_info,
	struct xt_trace_sink_config_info *config_info, uint64_t write_point,
	uint64_t offset, uint64_t buffer_size, uint8_t *buffer)
{
	uint64_t trace_data_start_address =
		config_info->ram_sink_start + offset;
	uint64_t first_size;
	uint64_t second_size;

	if (config_info->ram_sink_stop_on_wrap == 0 && (write_point & 0x1) == 1)
		trace_data_start_address =
			(write_point & 0xfffffffffffffffc) + offset;

	if (buffer_size >
	    ((config_info->ram_sink_limit + config_info->ram_sink_start) * 2)) {
		// msg
		return 1;
	}

	if (trace_data_start_address >= config_info->ram_sink_limit) {
		if (buffer_size > (config_info->ram_sink_limit +
				   config_info->ram_sink_start)) {
			// msg
			return 1;
		}

		trace_data_start_address = config_info->ram_sink_start +
					   (trace_data_start_address -
					    config_info->ram_sink_limit);
		first_size = buffer_size;
		second_size = 0;
	} else {
		if ((trace_data_start_address + buffer_size) >
		    config_info->ram_sink_limit) {
			first_size = config_info->ram_sink_limit -
				     trace_data_start_address;
			second_size = buffer_size - first_size;
		} else {
			first_size = buffer_size;
			second_size = 0;
		}
	}

	if (config_info->type == TRACE_SMEM_SINK) {
		/*FIXME: memcpy ???  */
		if (first_size) {
			if (xt_trace_read_data_from_smem_sink(
				    sink_info->base_addr,
				    trace_data_start_address, first_size,
				    buffer))
				return -1;
		}
		if (second_size) {
			if (xt_trace_read_data_from_smem_sink(
				    sink_info->base_addr,
				    config_info->ram_sink_start, second_size,
				    buffer + first_size))
				return -1;
		}
	} else {
		if (first_size) {
			if (xt_trace_read_data_from_sram_sink(
				    sink_info->base_addr,
				    trace_data_start_address, first_size,
				    buffer))
				return -1;
		}
		if (second_size) {
			if (xt_trace_read_data_from_sram_sink(
				    sink_info->base_addr,
				    config_info->ram_sink_start, second_size,
				    buffer + first_size))
				return -1;
		}
	}

	return 0;
}
