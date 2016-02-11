/*
 Copyright (C) 2016, OVH SAS

 This file is part of phishing-mitigation.

 phishing-mitigation is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#include "ovh_cpu.h"

cpu_set_t normal_cpus;
cpu_set_t dataplane_cpus;


void ovh_cpu_init(int work_size)
{
  PRINT_D5("setting up cpus...\n");

  // Make sure we have enough cpus.
  if (tmc_cpus_get_online_cpus(&normal_cpus))
    tmc_task_die("Failure in 'tmc_cpus_get_online_cpus()'.");
  if (tmc_cpus_get_dataplane_cpus(&dataplane_cpus))
    tmc_task_die("Failure in 'tmc_cpus_get_dataplane_cpus()'.");
  tmc_cpus_remove_cpus(&normal_cpus, &dataplane_cpus);
  // We need 'work_size + 1' dataplane cpus (workers + GC)
  if (tmc_cpus_count(&dataplane_cpus) < work_size + 1)
    tmc_task_die("Insufficient dataplane cpus available.");
  // We need just 1 normal cpus (main + logger)
  if (tmc_cpus_count(&normal_cpus) < 1)
    tmc_task_die("Insufficient normal cpus available.");

  if (tmc_cpus_set_my_cpu(tmc_cpus_find_nth_cpu(&normal_cpus, 0)) < 0)
    tmc_task_die("Failure in 'tmc_cpus_set_my_cpu()'.");

}
