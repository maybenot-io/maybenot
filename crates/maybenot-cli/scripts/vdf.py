#!/usr/bin/env python3

# Code from the paper: August Carlson, David Hasselquist, Ethan Witwer, Niklas
# Johansson, and Niklas Carlsson. "Understanding and Improving Video
# Fingerprinting Attack Accuracy under Challenging Conditions". 23rd Workshop on
# Privacy in the Electronic Society (WPES '24), 2024. If you use this code in
# your work, please include a reference to the paper. More details are available
# in README.md

"""
Runs Deep Fingerorinting (DF) by Sirinam et al., from the paper "Deep
Fingerprinting: Undermining Website Fingerprinting Defenses with Deep
Learning", ACM CCS 2018.

Modified to work with our dataset structure and splitting.
"""

import argparse
import os
import sys
import numpy as np
import random
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils import data
from multiprocessing import Pool
import datetime
import csv

# Directory to load cross-validation splits from
# Files have the format "X.txt", where X is the number of subpages.
CROSS_VALIDATION_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "cross-validation/"
)

# Model hyperparameters
EPOCH = 200
BATCH_SIZE = 250
INPUT_LENGTH = 5000

ap = argparse.ArgumentParser()
# dataset and its dimensions
ap.add_argument(
    "-d", required=True, default="", help="root folder of client/server dataset"
)
ap.add_argument(
    "-c",
    required=True,
    type=int,
    default=100,
    help="the number of monitored videos (=classes)",
)
ap.add_argument("-p", type=int, default=10, help="the number of offsets")
ap.add_argument(
    "-s",
    required=True,
    type=int,
    default=10,
    help="the number of samples per offset to load",
)
ap.add_argument(
    "-w",
    required=False,
    type=int,
    default=24,
    help="number of workers for loading traces from disk",
)

ap.add_argument(
    "--lm", required=False, default="", help="load model from provided path"
)
ap.add_argument("--sm", required=False, default="", help="save model to provided path")

ap.add_argument(
    "--min",
    required=False,
    type=int,
    default=0,
    help="smallest packet size to consider",
)

ap.add_argument(
    "--train", required=False, default=False, action="store_true", help="train model"
)

ap.add_argument("--epochs", required=False, default=EPOCH, help="epochs, ignored")
ap.add_argument("--patience", required=False, default=EPOCH, help="patience, ignored")
ap.add_argument(
    "--seed", required=False, type=int, default=-1, help="seed for reproducibility"
)
ap.add_argument(
    "-l", required=False, default=False, action="store_true", help="ignored"
)
ap.add_argument(
    "-f",
    required=False,
    type=int,
    default=0,
    help="the fold number, offset to the cross file",
)


ap.add_argument(
    "--constant",
    required=False,
    default=False,
    action="store_true",
    help="simulate constant-size padding (default DF)",
)
ap.add_argument(
    "--tiktok",
    required=False,
    default=False,
    action="store_true",
    help="use directional time, ignoring packet sizes",
)

## extra output
ap.add_argument(
    "--csv",
    required=False,
    default=None,
    help="save resulting metrics to provided path in csv format",
)
ap.add_argument(
    "--extra", required=False, default="", help="value of extra column in csv output"
)

args = vars(ap.parse_args())


def now():
    return datetime.datetime.now().strftime("%H:%M:%S")


def main():
    if args["seed"] > -1:
        set_seed(args["seed"])
        print(f"{now()} using deterministic seed {args['seed']}")
    dataset, labels = {}, {}
    if not os.path.isdir(args["d"]):
        sys.exit(f"{args['d']} is not a directory")

    if args["constant"]:
        print(f"{now()} starting to load dataset from {args['d']} (default DF)")
    elif args["tiktok"]:
        print(f"{now()} starting to load dataset from {args['d']} (with Tik-Tok)")
    else:
        print(f"{now()} starting to load dataset from {args['d']} (with packet sizes)")

    dataset, labels = load_dataset_star(
        args["d"],
        args["c"],
        args["p"],
        args["s"],
        INPUT_LENGTH,
        log2constants
        if args["constant"]
        else log2tiktok
        if args["tiktok"]
        else log2packets,
    )

    print(f"{now()} loaded {len(dataset)} items in dataset with {len(labels)} labels")

    if args["constant"]:
        print("using constant-size packets")
    else:
        print("using actual packet sizes")

    split = split_dataset(args["c"], args["p"], args["s"], args["f"])
    print(
        f"{now()} split {len(split['train'])} training, "
        f"{len(split['validation'])} validation, and "
        f"{len(split['test'])} testing"
    )

    model = DFNet(args["c"])
    if args["lm"] != "":
        model = torch.load(args["lm"])
        print(f"loaded model from {args['lm']}")

    device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
    if torch.cuda.is_available():
        print(f"{now()} using {torch.cuda.get_device_name(0)}")
        model.cuda()

    if args["train"]:
        # Note below that shuffle=True is *essential*,
        # see https://stackoverflow.com/questions/54354465/
        train_gen = data.DataLoader(
            Dataset(split["train"], dataset, labels),
            batch_size=BATCH_SIZE,
            shuffle=True,
        )
        validation_gen = data.DataLoader(
            Dataset(split["validation"], dataset, labels),
            batch_size=BATCH_SIZE,
            shuffle=True,
        )

        optimizer = torch.optim.Adamax(params=model.parameters())
        criterion = torch.nn.CrossEntropyLoss()

        for epoch in range(EPOCH):
            print(f"{now()} epoch {epoch}")

            # training
            model.train()
            torch.set_grad_enabled(True)
            running_loss = 0.0
            n = 0
            for x, Y in train_gen:
                x, Y = x.to(device), Y.to(device)
                optimizer.zero_grad()
                outputs = model(x)
                loss = criterion(outputs, Y)
                loss.backward()
                optimizer.step()
                running_loss += loss.item()
                n += 1
            print(f"\ttraining loss {running_loss / n}")

            # validation
            model.eval()
            torch.set_grad_enabled(False)
            running_corrects = 0
            n = 0
            for x, Y in validation_gen:
                x, Y = x.to(device), Y.to(device)

                outputs = model(x)
                _, preds = torch.max(outputs, 1)
                running_corrects += torch.sum(preds == Y)
                n += len(Y)
            print(f"\tvalidation accuracy {float(running_corrects) / float(n)}")

        if args["sm"] != "":
            torch.save(model, args["sm"])
            print(f"saved model to {args['sm']}")

    # testing
    testing_gen = data.DataLoader(
        Dataset(split["test"], dataset, labels), batch_size=BATCH_SIZE
    )
    model.eval()
    torch.set_grad_enabled(False)
    predictions = []
    p_labels = []
    for x, Y in testing_gen:
        x = x.to(device)
        outputs = model(x)
        index = F.softmax(outputs, dim=1).data.cpu().numpy()
        predictions.extend(index.tolist())
        p_labels.extend(Y.data.numpy().tolist())

    print(f"{now()} made {len(predictions)} predictions with {len(p_labels)} labels")
    csvline = []
    threshold = np.append([0], 1.0 - 1 / np.logspace(0.05, 2, num=15, endpoint=True))
    threshold = np.around(threshold, decimals=4)
    for th in threshold:
        tp, fp, fn, accuracy, label_right, label_total = metrics(
            th, predictions, p_labels
        )
        print(
            f"\tthreshold {th:4.2}, "
            f"accuracy {accuracy:4.2}   "
            f"[tp {tp:>5}, fp {fp:>5}, fn {fn:>5}]"
        )
        if th == 0:
            print("\t\t", end="")
            n = 0
            for key, value in sorted(label_right.items(), key=lambda x: x[0]):
                r = value / label_total[key]
                print(f"{key:>2} {r:>5}, ", end=" ")
                n += 1
                if n == 10:
                    print("")
                    print("\t\t", end="")
                    n = 0
            print("")
        csvline.append([th, accuracy, tp, fp, fn, args["extra"]])
    tp, fp, fn, accuracy, label_right, label_total = metrics(0, predictions, p_labels)
    print(accuracy)

    if args["csv"]:
        with open(args["csv"], "w", newline="") as csvfile:
            w = csv.writer(csvfile, delimiter=",")
            w.writerow(["th", "accuracy", "tp", "fp", "fn", "extra"])
            w.writerows(csvline)
        print(f"saved testing results to {args['csv']}")


class DFNet(nn.Module):
    def __init__(self, classes, fc_in_features=512 * 10):
        super(DFNet, self).__init__()
        # https://ezyang.github.io/convolution-visualizer/index.html
        # https://github.com/lin-zju/deep-fp/blob/master/lib/modeling/backbone/dfnet.py
        self.kernel_size = 7
        self.padding_size = 3
        self.pool_stride_size = 4
        self.pool_size = 7

        self.block1 = self.__block(1, 32, nn.ELU())
        self.block2 = self.__block(32, 64, nn.ReLU())
        self.block3 = self.__block(64, 128, nn.ReLU())
        self.block4 = self.__block(128, 256, nn.ReLU())

        self.fc = nn.Sequential(
            nn.Linear(fc_in_features, 512),
            nn.BatchNorm1d(512),
            nn.ReLU(),
            nn.Dropout(0.7),
            nn.Linear(512, 512),
            nn.BatchNorm1d(512),
            nn.ReLU(),
            nn.Dropout(0.5),
        )

        self.prediction = nn.Sequential(
            nn.Linear(512, classes),
            # when using CrossEntropyLoss, already computed internally
            # nn.Softmax(dim=1) # dim = 1, don't softmax batch
        )

    def __block(self, channels_in, channels, activation):
        return nn.Sequential(
            nn.Conv1d(
                channels_in, channels, self.kernel_size, padding=self.padding_size
            ),
            nn.BatchNorm1d(channels),
            activation,
            nn.Conv1d(channels, channels, self.kernel_size, padding=self.padding_size),
            nn.BatchNorm1d(channels),
            activation,
            nn.MaxPool1d(
                self.pool_size, stride=self.pool_stride_size, padding=self.padding_size
            ),
            nn.Dropout(p=0.1),
        )

    def forward(self, x):
        x = self.block1(x)
        x = self.block2(x)
        x = self.block3(x)
        x = self.block4(x)
        x = x.flatten(start_dim=1)  # dim = 1, don't flatten batch
        x = self.fc(x)
        x = self.prediction(x)

        return x


def parse_trace(fname, ID, length, extract_func):
    with open(fname, "r") as f:
        return (ID, extract_func(f.read(), length))


def load_dataset_star(folder, classes, subpages, samples, length, extract_func):
    """Loads the dataset from disk into two dictionaries for data and labels."""
    labels = {}

    # starmap into todo
    todo = []
    for c in range(0, classes):
        for p in range(0, subpages):
            for s in range(0, samples):
                ID = to_file_label(c, p, s)
                labels[ID] = c
                # file format is {site}-{sample}.trace
                fname = f"{ID}.log"
                todo.append(
                    (os.path.join(folder, str(c), fname), ID, length, extract_func)
                )

    # starmap do results
    p = Pool(args["w"])
    results = p.starmap(parse_trace, todo)

    # assemble results
    data = {}
    for result in results:
        data[result[0]] = result[1]

    return data, labels


def to_file_label(c, sub, sample):
    return f"{int(c):04d}-{int(sub):04d}-{int(sample):04d}"


class Dataset(data.Dataset):
    def __init__(self, ids, dataset, labels):
        self.ids = ids
        self.dataset = dataset
        self.labels = labels

    def __len__(self):
        return len(self.ids)

    def __getitem__(self, index):
        ID = self.ids[index]
        return self.dataset[ID], self.labels[ID]


def split_dataset(websites, subpages, samples, fold):
    """Splits the dataset based on fold.

    The split is only based on IDs, not the actual data. The result is a 8:1:1
    split into training, validation, and testing.
    """
    training = []
    validation = []
    testing = []

    # the split is made on subpages
    split_file = open(f"{CROSS_VALIDATION_DIR}{subpages}.txt")
    split_file_str = split_file.read()
    split_list = split_file_str.split("\n")
    for c in range(0, websites):
        test_index = (int(split_list[c].split(",")[0]) + fold) % subpages
        validation_index = (int(split_list[c].split(",")[1]) + fold) % subpages
        for p in range(0, subpages):
            for s in range(0, samples):
                ID = to_file_label(c, p, s)
                if p == test_index:
                    testing.append(ID)
                elif p == validation_index:
                    validation.append(ID)
                else:
                    training.append(ID)

    split = {}
    split["train"] = training
    split["validation"] = validation
    split["test"] = testing
    return split


def metrics(threshold, predictions, labels):
    """Computes a range of metrics.

    For details on the metrics, see, e.g., https://www.cs.kau.se/pulls/hot/baserate/
    """
    tp, fp, fn, accuracy = 0, 0, 0, 0.0

    # extended metric: per-class monitored stats
    label_right = {}
    label_total = {}

    for i in range(len(predictions)):
        label_pred = np.argmax(predictions[i])
        prob_pred = max(predictions[i])
        label_correct = labels[i]

        # total +1
        label_total[label_correct] = label_total.get(label_correct, 0) + 1

        # hack to get every label in the dict, not incrementing
        label_right[label_correct] = label_right.get(label_correct, 0)

        # either confident and correct,
        if prob_pred >= threshold and label_pred == label_correct:
            tp = tp + 1
            label_right[label_pred] = label_right.get(label_pred, 0) + 1
        # confident and wrong monitored label, or
        elif prob_pred >= threshold:
            fp = fp + 1
        # wrong because not confident enough
        else:
            fn = fn + 1

    accuracy = round(float(tp) / float(tp + fp + fn), 4)

    return tp, fp, fn, accuracy, label_right, label_total


MAX_MATRIX_LEN = 4000
MAXIMUM_LOAD_TIME = 60.0


def log2packets(log, length):
    """transform a log to a one-dimensional numpy array of packet sizes with
    direction (time series)
    """
    data = np.zeros((1, length), dtype=np.float32)

    n = 0
    s = log.split("\n")
    interval = 1000 * 1000 * 1000 * MAXIMUM_LOAD_TIME / MAX_MATRIX_LEN
    current_interval_max = interval

    last_index = len(s) - 1
    last_time = None
    while last_time is None:
        try:
            last_time = float(s[last_index].split(",")[0])
        except:
            last_index -= 1
            last_time = None

    for line in s:
        parts = line.split(",")
        if len(parts) < 3:
            break

        size = float(parts[2])
        if (
            size < args["min"]
            or float(parts[0]) < last_time - 1000 * 1000 * 1000 * MAXIMUM_LOAD_TIME
        ):
            continue

        while (
            float(parts[0]) - (last_time - 1000 * 1000 * 1000 * MAXIMUM_LOAD_TIME)
            > current_interval_max
        ):
            current_interval_max += interval
            n += 1

        if n >= MAX_MATRIX_LEN:
            break

        # sent is positive
        if "s" in parts[1]:
            data[0][n] += 1.0 * size
        # received is negative
        elif "r" in parts[1]:
            data[0][n] += -1.0 * size

    return data


def log2tiktok(log, length):
    """transform a log to a one-dimensional numpy array of directional time"""
    data = np.zeros((1, length), dtype=np.float32)
    n = 0

    def convert(s):
        # first we turn into seconds, then we cut all but .1 ms resolution
        seconds = float(s) / float(1 * 1000 * 1000 * 1000)
        return float(f"{seconds:.4f}")

    s = log.split("\n")

    last_index = len(s) - 1
    last_time = None
    while last_time is None:
        try:
            last_time = float(s[last_index].split(",")[0])
        except:
            last_index -= 1
            last_time = None

    for line in s:
        parts = line.split(",")
        if len(parts) < 3:
            break

        size = float(parts[2])
        if (
            size < args["min"]
            or float(parts[0]) < last_time - 1000 * 1000 * 1000 * MAXIMUM_LOAD_TIME
        ):
            continue

        # sent is positive
        if "s" in parts[1]:
            data[0][n] = 1.0 * convert(parts[0])
            n += 1
        # received is negative
        elif "r" in parts[1]:
            data[0][n] = -1.0 * convert(parts[0])
            n += 1

        if n == length:
            break

    return data


def log2constants(log, length):
    """transform a log to a one-dimensional numpy array of packet directions, ignoring length."""
    data = np.zeros((1, length), dtype=np.float32)
    n = 0

    s = log.split("\n")

    last_index = len(s) - 1
    last_time = None
    while last_time is None:
        try:
            last_time = float(s[last_index].split(",")[0])
        except:
            last_index -= 1
            last_time = None

    for line in s:
        parts = line.split(",")
        if len(parts) < 3:
            break

        size = float(parts[2])
        if (
            size < args["min"]
            or float(parts[0]) < last_time - 1000 * 1000 * 1000 * MAXIMUM_LOAD_TIME
        ):
            continue

        # sent is positive
        if "s" in parts[1]:
            data[0][n] = 1.0
            n += 1
        # received is negative
        elif "r" in parts[1]:
            data[0][n] = -1.0
            n += 1

        if n == length:
            break

    return data


def set_seed(seed):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)  # if using multi-GPU
    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False


if __name__ == "__main__":
    main()
