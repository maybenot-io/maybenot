#!/usr/bin/env python3
import argparse
import os
import sys
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils import data
from multiprocessing import Pool
import datetime
import csv
import random

ap = argparse.ArgumentParser()
# dataset and its dimensions
ap.add_argument(
    "-d", required=True, default="", help="root folder of client/server dataset"
)
ap.add_argument(
    "-c",
    required=False,
    type=int,
    default=92,
    help="the number of monitored websites (=classes)",
)
ap.add_argument(
    "-p", required=False, type=int, default=10, help="the number of subpages"
)
ap.add_argument(
    "-s",
    required=False,
    type=int,
    default=20,
    help="the number of samples per subpage to load",
)
ap.add_argument(
    "-w",
    required=False,
    type=int,
    default=10,
    help="number of workers for loading traces from disk",
)

ap.add_argument(
    "--lm", required=False, default="", help="load model from provided path"
)
ap.add_argument("--sm", required=False, default="", help="save model to provided path")

ap.add_argument(
    "--train", required=False, default=False, action="store_true", help="train model"
)

ap.add_argument(
    "--packetsizes",
    required=False,
    default=False,
    action="store_true",
    help="use packet sizes, i.e., directional size",
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
    help="save resulting metrics in provided path in csv format",
)
ap.add_argument(
    "--extra", required=False, default="", help="value of extra column in csv output"
)

# experiment parameters
ap.add_argument(
    "--epochs",
    required=False,
    type=int,
    default=30,
    help="the number of epochs for training",
)
ap.add_argument(
    "--patience",
    required=False,
    type=int,
    default=10,
    help="the number of epochs for early stopping",
)
ap.add_argument("--batchsize", required=False, type=int, default=256, help="batch size")
ap.add_argument(
    "-f", required=False, type=int, default=0, help="the fold number (partition offset)"
)
ap.add_argument(
    "-l",
    required=False,
    default=False,
    action="store_true",
    help="large (10k) input length, else 5k",
)
ap.add_argument(
    "--seed", required=False, type=int, default=-1, help="seed for reproducibility"
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

    numpackets = "5k packets/trace" if not args["l"] else "10k packets/trace"

    if args["packetsizes"]:
        print(
            f"{now()} starting to load dataset from {args['d']} (with packet sizes), {numpackets}"
        )
    elif args["tiktok"]:
        print(
            f"{now()} starting to load dataset from {args['d']} (with Tik-Tok), {numpackets}"
        )
    else:
        print(
            f"{now()} starting to load dataset from {args['d']} (default DF), {numpackets})"
        )

    # check for dataset/0/0000-0000-0000.log or dataset/0/0.log
    subpages = os.path.exists(os.path.join(args["d"], "0", "0000-0000-0000.log"))
    samples = os.path.exists(os.path.join(args["d"], "0", "0.log"))
    if not subpages and not samples:
        sys.exit(f"{args['d']} does not contain subpages or samples")
    if subpages and samples:
        sys.exit(f"{args['d']} contains both subpages and samples")
    print(f"{now()} using subpages" if subpages else f"{now()} using samples")

    dataset, labels = load_dataset(
        args["d"],
        args["c"],
        None if samples else args["p"],
        args["s"],
        5000 if not args["l"] else 10000,
        log2packets
        if args["packetsizes"]
        else log2tiktok
        if args["tiktok"]
        else log2constants,
    )

    print(f"{now()} loaded {len(dataset)} items in dataset with {len(labels)} labels")

    if args["packetsizes"]:
        print("using packets sizes")
    elif args["tiktok"]:
        print("using Tik-Tok")
    else:
        print("default DF, just direction of packets")

    split = (
        split_dataset_samples(args["c"], args["s"], args["f"], labels)
        if samples
        else split_dataset_subpages(args["c"], args["p"], args["s"], args["f"], labels)
    )
    print(
        f"{now()} split {len(split['train'])} training and {len(split['test'])} testing"
    )

    model = DF(args["c"], args["l"])
    if args["lm"] != "":
        model = torch.load(args["lm"], weights_only=False)
        print(f"loaded model from {args['lm']}")

    device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
    if torch.cuda.is_available():
        print(f"{now()} using {torch.cuda.get_device_name(0)}")
        model.cuda()

    if args["train"]:
        print(
            f"{now()} starting training with {args['epochs']} epochs and patience {args['patience']}"
        )
        # Note below that shuffle=True is *essential*,
        # see https://stackoverflow.com/questions/54354465/
        train_gen = data.DataLoader(
            Dataset(split["train"], dataset, labels),
            batch_size=args["batchsize"],
            shuffle=True,
        )
        optimizer = torch.optim.Adamax(params=model.parameters())
        criterion = torch.nn.CrossEntropyLoss()
        best_loss = float("inf")
        patience = args["patience"]

        for epoch in range(args["epochs"]):
            print(f"{now()} epoch {epoch}")

            # training
            model.train()
            torch.set_grad_enabled(True)
            running_loss = 0.0
            accuracy = 0.0
            n = 0
            for x, Y in train_gen:
                x, Y = x.to(device), Y.to(device)
                optimizer.zero_grad()
                outputs = model(x)
                _, a = get_result(outputs.cpu(), Y.cpu())

                loss = criterion(outputs, Y)
                loss.backward()
                optimizer.step()
                running_loss += loss.item()
                accuracy += a
                n += 1

            print(f"\ttraining loss {running_loss / n:.4f}")
            print(f"\ttraining accuracy {accuracy / n:.4f}")
            if running_loss < best_loss:
                best_loss = running_loss
                patience = args["patience"]
            else:
                patience -= 1
                if patience == 0:
                    print(f"\tearly stopping, patience {args['patience']} reached")
                    break

        if args["sm"] != "":
            torch.save(model, args["sm"])
            print(f"saved model to {args['sm']}")

    # testing
    testing_gen = data.DataLoader(
        Dataset(split["test"], dataset, labels), batch_size=args["batchsize"]
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

    if args["csv"]:
        with open(args["csv"], "w", newline="") as csvfile:
            w = csv.writer(csvfile, delimiter=",")
            w.writerow(["th", "accuracy", "tp", "fp", "fn", "extra"])
            w.writerows(csvline)
        print(f"saved testing results to {args['csv']}")

    tp, fp, fn, accuracy, label_right, label_total = metrics(0, predictions, p_labels)
    print(accuracy)


def get_result(output, true_y):
    pred_y = torch.max(output, 1)[1].data.numpy().squeeze()
    accuracy = (pred_y == true_y.numpy()).sum().item() * 1.0 / float(true_y.size(0))
    return pred_y, accuracy


# from https://github.com/Xinhao-Deng/Website-Fingerprinting-Library/blob/master/WFlib/models/DF.py
class ConvBlock(nn.Module):
    def __init__(
        self,
        in_channels,
        out_channels,
        kernel_size,
        stride,
        pool_size,
        pool_stride,
        dropout_p,
        activation,
    ):
        super(ConvBlock, self).__init__()
        padding = (
            kernel_size // 2
        )  # Calculate padding to keep the output size same as input size
        # Define a convolutional block consisting of two convolutional layers, each followed by batch normalization and activation
        self.block = nn.Sequential(
            nn.Conv1d(
                in_channels,
                out_channels,
                kernel_size,
                stride,
                padding=padding,
                bias=False,
            ),  # First convolutional layer
            nn.BatchNorm1d(out_channels),  # Batch normalization layer
            activation(inplace=True),  # Activation function (e.g., ELU or ReLU)
            nn.Conv1d(
                out_channels,
                out_channels,
                kernel_size,
                stride,
                padding=padding,
                bias=False,
            ),  # Second convolutional layer
            nn.BatchNorm1d(out_channels),  # Batch normalization layer
            activation(inplace=True),  # Activation function
            nn.MaxPool1d(
                pool_size, pool_stride, padding=0
            ),  # Max pooling layer to downsample the input
            nn.Dropout(p=dropout_p),  # Dropout layer for regularization
        )

    def forward(self, x):
        # Pass the input through the convolutional block
        return self.block(x)


# from https://github.com/Xinhao-Deng/Website-Fingerprinting-Library/blob/master/WFlib/models/DF.py
class DF(nn.Module):
    def __init__(self, num_classes, large_input=False):
        super(DF, self).__init__()

        # Configuration parameters for the convolutional blocks
        filter_num = [32, 64, 128, 256]  # Number of filters for each block
        kernel_size = 8  # Kernel size for convolutional layers
        conv_stride_size = 1  # Stride size for convolutional layers
        pool_stride_size = 4  # Stride size for max pooling layers
        pool_size = 8  # Kernel size for max pooling layers
        length_after_extraction = (
            18  # Length of the feature map after the feature extraction part
        )

        # Define the feature extraction part of the network using a sequential container with ConvBlock instances
        self.feature_extraction = nn.Sequential(
            ConvBlock(
                1,
                filter_num[0],
                kernel_size,
                conv_stride_size,
                pool_size,
                pool_stride_size,
                0.1,
                nn.ELU,
            ),  # Block 1
            ConvBlock(
                filter_num[0],
                filter_num[1],
                kernel_size,
                conv_stride_size,
                pool_size,
                pool_stride_size,
                0.1,
                nn.ReLU,
            ),  # Block 2
            ConvBlock(
                filter_num[1],
                filter_num[2],
                kernel_size,
                conv_stride_size,
                pool_size,
                pool_stride_size,
                0.1,
                nn.ReLU,
            ),  # Block 3
            ConvBlock(
                filter_num[2],
                filter_num[3],
                kernel_size,
                conv_stride_size,
                pool_size,
                pool_stride_size,
                0.1,
                nn.ReLU,
            ),  # Block 4
        )

        # Define the classifier part of the network
        self.classifier = nn.Sequential(
            nn.Flatten(),  # Flatten the tensor to a vector
            nn.Linear(
                9728 if large_input else filter_num[3] * length_after_extraction,
                512,
                bias=False,
            ),  # Fully connected layer
            nn.BatchNorm1d(512),  # Batch normalization layer
            nn.ReLU(inplace=True),  # ReLU activation function
            nn.Dropout(p=0.7),  # Dropout layer for regularization
            nn.Linear(512, 512, bias=False),  # Fully connected layer
            nn.BatchNorm1d(512),  # Batch normalization layer
            nn.ReLU(inplace=True),  # ReLU activation function
            nn.Dropout(p=0.5),  # Dropout layer for regularization
            nn.Linear(512, num_classes),  # Output layer
        )

    def forward(self, x):
        # Pass the input through the feature extraction part
        x = self.feature_extraction(x)

        # Pass the output through the classifier part
        x = self.classifier(x)

        return x


def parse_trace(fname, ID, length, extract_func):
    with open(fname, "r") as f:
        return (ID, extract_func(f.read(), length))


def load_dataset(folder, classes, subpages, samples, length, extract_func):
    """Loads the dataset from disk into two dictionaries for data and labels.

    If subpages is None, the dataset is loaded as samples per class. Otherwise,
    the dataset is loaded as subpages per class.
    """
    labels = {}

    # starmap into todo
    todo = []
    if subpages is None:
        for c in range(0, classes):
            for s in range(0, samples):
                ID = f"{c}-{s}"
                labels[ID] = c
                # file format is {sample}.log
                fname = f"{s}.log"
                todo.append(
                    (os.path.join(folder, str(c), fname), ID, length, extract_func)
                )
    else:
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


def split_dataset_subpages(websites, subpages, samples, fold, labels):
    """Splits the dataset based on fold into 8:2.

    Splits based on subpages, not individual samples.
    """
    training = []
    testing = []

    # the split is made on subpages
    for c in range(0, websites):
        for p in range(0, subpages):
            for s in range(0, samples):
                ID = to_file_label(c, p, s)

                i = (p + fold) % subpages
                if i < subpages - 2:
                    training.append(ID)
                else:
                    testing.append(ID)

    split = {}
    split["train"] = training
    split["test"] = testing
    return split


def split_dataset_samples(classes, samples, fold, labels):
    """Splits the dataset based on fold into 8:2.

    Splits based on samples, not subpages.
    """
    training = []
    testing = []

    for c in range(0, classes):
        for s in range(0, samples):
            ID = f"{c}-{s}"

            i = (s + fold) % 10
            if i < 8:
                training.append(ID)
            else:
                testing.append(ID)

    split = {}
    split["train"] = training
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


def log2packets(log, length):
    """transform a log to a one-dimensional numpy array of packet-sizes with
    direction.
    """
    data = np.zeros((1, length), dtype=np.float32)
    n = 0

    s = log.split("\n")
    for line in s:
        parts = line.split(",")
        if len(parts) < 3:
            break

        size = float(pad_wg_packet_len(int(parts[2])))

        # sent is positive
        if "s" in parts[1]:
            data[0][n] = 1.0 * size
            n += 1
        # received is negative
        elif "r" in parts[1]:
            data[0][n] = -1.0 * size
            n += 1

        if n == length:
            break

    return data


def pad_wg_packet_len(length, mtu=1420):
    """
    WireGuard packets are padded to multiples of 16 bytes. Taking away headers
    is fine (just a constant), but without padding, we give the attacker more
    information than available in the real world due to the data collection
    being from events from the Maybenot framework (inside the tunnel).

    The result is just the smallest of the MTU or length padded to the next 16
    bytes.
    """
    return min(mtu, length + (16 - (length % 16)))


def log2tiktok(log, length):
    """transform a log to a one-dimensional numpy array of directional time."""
    data = np.zeros((1, length), dtype=np.float32)
    n = 0

    def convert(s):
        # first we turn into seconds, then we cut all but .1 ms resolution
        seconds = float(s) / float(1000 * 1000 * 1000)
        return float(f"{seconds:.4f}")

    s = log.split("\n")
    for line in s:
        parts = line.split(",")
        if len(parts) < 2:
            break

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
    """
    transform a log to a one-dimensional numpy array of packet-directions,
    ignoring length.
    """
    data = np.zeros((1, length), dtype=np.float32)
    n = 0

    s = log.split("\n")
    for line in s:
        parts = line.split(",")
        if len(parts) < 2:
            break

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
